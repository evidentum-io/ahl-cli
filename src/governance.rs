//! Governance resolved from anchored entries, independently of any receipt.
//!
//! `ahl-core` resolves governance inside `verify_receipt`, from the chain a receipt carries.
//! A client that must resolve it from a **live enumeration** — which `closure` and
//! `reconstruct` do — needs the same rules over a different input, and `ahl-core` does not
//! expose them, so they are re-derived here against the same normative text.
//!
//! The rules, and why each one is not optional:
//!
//! * **Governance statements are not self-authorizing** (core spec §7.3, adaptor §7.4.1).
//!   Anchoring proves bytes existed at a position; it never makes an unverified governance
//!   statement effective. A party able to submit entries can place a well-formed object
//!   claiming to be a manifest at a real index with a real inclusion proof, and a verifier
//!   that resolved keys from it would accept checkpoints signed by keys the corpus never
//!   adopted.
//! * **The genesis anchor comes from local policy**, never from the log.
//! * **A manifest's `keys` array is a snapshot, not a set of add events** (core spec §7.2): it
//!   discards the prior snapshot, and later `key` statements modify it in entry order until
//!   the next manifest version. A key a later manifest omits is gone.
//! * **The manifest version governing a checkpoint is selected by `tree_size`** — the manifest
//!   statement with the greatest entry index smaller than that `tree_size` (core spec §7.3,
//!   receipt format §2.2). Resolving by the *subject entry's* index is wrong in both
//!   directions: it rejects a legitimate rotation between the entry and the checkpoint, and it
//!   admits a retired key on a later checkpoint.
//!
//! # Governance is not self-authorizing, and this is where that is enforced
//!
//! Adaptor §7.4.1 is explicit that an implementation built from the profile alone could
//! otherwise "resolve keys from any anchored entry whose payload says `"type": "manifest"`. It
//! MUST NOT." An anchored `manifest` or `key` statement counts as governance only if **all**
//! of the following hold:
//!
//! 1. it is anchored at a known entry index, proven by inclusion under a checkpoint — which is
//!    established before [`Governance::resolve`] is reached, by the range proof and the root
//!    recomputation of [`crate::enumerate`];
//! 2. its **producer signature verifies under the key set in force at its own entry index**,
//!    every signature entry resolving to an active key and verifying;
//! 3. for a non-genesis manifest, its `predecessor` links by entry id to the manifest version
//!    **active immediately before it** — not merely to some earlier manifest in the log;
//! 4. for the genesis manifest, its entry id and initial key fingerprints match the verifier's
//!    **locally configured** trust anchor, which is never taken from the log.
//!
//! Test 2 is why [`Governance::resolve`] builds the chain **incrementally**. Collecting every
//! `manifest`-shaped payload first and checking signatures afterwards inverts the dependency:
//! a hostile mirror can then serve a recomputable tree containing the genuine pinned genesis
//! manifest *plus a forged later manifest naming attacker log keys*, and a checkpoint signed
//! by those keys authenticates. On a log without submission controls anyone who can reach the
//! endpoint can place such an entry at a real index with a real inclusion proof.
//!
//! A statement that fails is **ignored for key resolution and reported**, never fatal: adaptor
//! §7.4.1 says such an entry "is not a fork of the corpus and does not need to be reconciled
//! with the real chain". Only a genesis that does not match configured policy is fatal, because
//! then there is no trust anchor at all.
//!
//! # `log.log_id`
//!
//! Core §7.2/§7.3 and adaptor §7.3 name the manifest log-object member `log_id`, and every
//! member of that object is REQUIRED. This module requires that spelling: the value is
//! load-bearing for the check that a checkpoint belongs to the corpus's bound Data Tree
//! (adaptor §3, §6.2), so its absence is not a reportable irregularity but a check that cannot
//! be performed. Members this build never consults — `cadence_epoch`, `operator` — are
//! reported through [`Governance::log_object_findings`] instead, because reporting is all a
//! verifier can honestly do about a field no rule of its own depends on.
//!
use std::collections::{BTreeMap, BTreeSet};

use ahl_core::entry_id;
use ahl_core::receipt::TrustPolicy;
use serde_json::Value;

use crate::duration::parse_time_only_duration;
use crate::error::{CliError, CliResult};
use crate::report::Finding;

/// What a structural walk produced: the chain where one could be built, and — **always** —
/// every finding raised on the way to that answer.
///
/// The findings sit beside the result rather than inside its `Ok` arm, and that placement is
/// the whole point. A walk can reach a limit that leaves no usable chain *after* it has already
/// established, and recorded, exactly why: a corpus whose only manifest was excluded for
/// breaking the predecessor rule ends with no manifest, and the reason it ends that way is a
/// finding the walk is already holding. Returning it only on success would replace that
/// specific answer with a general one — "the chain does not resolve" — which is the same
/// suppression as ending the walk early, moved to the last line.
///
/// Design note §6 admits no such gap: in topology mode every violation found while walking is
/// reported, and nothing about reaching a limit makes the violations found before it less
/// found.
#[derive(Debug)]
pub struct StructuralWalk {
    /// The chain, or why no usable one remained. See [`Governance::structural_only`] for the
    /// two conditions that produce an error and why they are not findings.
    pub chain: CliResult<Governance>,
    /// Every violation found while walking, whether or not a chain remained.
    pub findings: Vec<Finding>,
}

impl StructuralWalk {
    /// A walk that reached a limit leaving no usable chain, carrying what it had already found.
    fn halted(detail: &str, mut findings: Vec<Finding>) -> Self {
        findings.sort();
        findings.dedup();
        Self { chain: Err(CliError::RuleFired(detail.to_owned())), findings }
    }
}

/// A producer key-set transition, ordered by the entry index that anchored it.
#[derive(Debug, Clone)]
struct KeyEvent {
    entry_index: u64,
    key_id: String,
    pubkey: String,
    added: bool,
}

/// The governance state derived from a set of anchored entries.
#[derive(Debug, Clone, Default)]
pub struct Governance {
    /// Manifest payloads, ascending by entry index.
    manifests: Vec<(u64, Value)>,
    /// Producer key transitions, ascending by entry index.
    events: Vec<KeyEvent>,
}

fn payload_of(envelope: &Value) -> CliResult<&Value> {
    envelope.get("payload").filter(|p| p.is_object()).ok_or_else(|| CliError::Malformed {
        what: "entry",
        detail: "carries no `payload` object".to_owned(),
    })
}

impl Governance {
    /// Collect governance statements after **structural validation only**, plus the findings
    /// raised while collecting them.
    ///
    /// No producer signature is checked and no trust anchor is consulted, so the result is
    /// **not** an authenticated key set and must never be used to authenticate anything. It
    /// exists for topology mode, where nothing is evidence and the point is to describe an
    /// operator-supplied file rather than to believe it. Authenticated callers use
    /// [`Self::resolve`].
    ///
    /// # Nothing found while walking may end the walk
    ///
    /// Design note §6 fixes topology mode's whole contract in one sentence: rule violations
    /// found while walking such a corpus are **findings, not verdicts — reported in full and
    /// never suppressed**, with the outcome fixed at `3`. A defect in one entry that ended the
    /// collection would silence every check that runs *after* it, so the corpus's remaining
    /// violations would vanish from the output — and the one thing this mode exists to produce
    /// is the list of violations. A shorter list is not a safer answer here; it is a wrong one.
    ///
    /// Every per-entry defect is therefore handled the way [`Self::resolve`] handles a
    /// structurally broken envelope: the element is **excluded and reported**, its position in
    /// the sequence is kept, and the walk continues. That covers an unreadable payload, a
    /// missing statement type, a manifest whose `predecessor` does not link to the version
    /// active immediately before it, and a `key` transition that is unusable — including one
    /// whose `key_id` does not recompute from its `pubkey`, which must never join a key set
    /// (core §2.3.6, adaptor §7.2) but equally must not take the rest of the corpus's report
    /// down with it.
    ///
    /// # Errors
    ///
    /// Only for the two conditions that leave nothing to walk *against* rather than something
    /// to report: entries that do not ascend by entry index, which is AHL's only ordering
    /// primitive, and a corpus carrying no manifest at all, which leaves no key set for any
    /// signature to be resolved against. The caller reports both — see [`crate::corpus::walk`],
    /// which says in as many words that signatures were not checked and why, rather than
    /// emitting a `signature-does-not-verify` for every entry whose real cause is the absent
    /// chain. Declaring every signature unverified there would not be noise but a false
    /// statement: with no key snapshot (core §7.2) and no determinate key-state order, whether
    /// a signature verifies is not a question this walk answered.
    ///
    /// **Reaching either limit never discards what the walk already found.** Both are returned
    /// through [`StructuralWalk`], whose findings are populated on the error path exactly as on
    /// the success path — a corpus whose only manifest was excluded for breaking the
    /// predecessor rule reports *that*, alongside the general answer that no chain remained.
    pub fn structural_only(entries: &[(u64, Value)]) -> StructuralWalk {
        let mut manifests: Vec<(u64, Value)> = Vec::new();
        let mut events: Vec<KeyEvent> = Vec::new();
        let mut findings: Vec<Finding> = Vec::new();
        let mut previous_manifest_entry_id: Option<String> = None;
        let mut previous_index: Option<u64> = None;

        let excluded = |index: &u64, detail: String| {
            Finding::new(
                "governance-element-excluded",
                format!(
                    "the entry at entry index {index} is excluded from the corpus's governance \
                     chain, its position in the sequence kept: {detail}. Nothing here is \
                     evidence, so this is reported and the walk continues"
                ),
            )
        };

        for (index, envelope) in entries {
            if previous_index.is_some_and(|previous| previous >= *index) {
                return StructuralWalk::halted(
                    "entries must ascend by entry index; the entry index is AHL's only \
                     ordering primitive",
                    findings,
                );
            }
            previous_index = Some(*index);

            let payload = match payload_of(envelope) {
                Ok(payload) => payload,
                Err(source) => {
                    findings.push(excluded(index, source.to_string()));
                    continue;
                }
            };
            let Some(kind) = payload.get("type").and_then(Value::as_str) else {
                findings.push(excluded(index, "it carries no statement type".to_owned()));
                continue;
            };
            match kind {
                "manifest" => {
                    let predecessor = payload.get("predecessor").and_then(Value::as_str);
                    let refusal = match (&previous_manifest_entry_id, predecessor) {
                        (None, Some(_)) => Some(
                            "the genesis manifest must carry no predecessor reference".to_owned(),
                        ),
                        (Some(_), None) => {
                            Some("a non-genesis manifest must reference its predecessor".to_owned())
                        }
                        // By *entry* id: signature identity matters for chain links (§2.3.5),
                        // and it must be the version active immediately before, not merely
                        // some earlier manifest in the log (adaptor §7.4.1 rule 3).
                        (Some(want), Some(got)) if want != got => Some(format!(
                            "it references `{got}`, but the version active immediately before \
                             it is `{want}`"
                        )),
                        _ => None,
                    };
                    if let Some(detail) = refusal {
                        findings.push(excluded(index, detail));
                        continue;
                    }
                    previous_manifest_entry_id = Some(entry_id(envelope));
                    manifests.push((*index, payload.clone()));
                }
                "key" => match read_key_event(*index, payload) {
                    Ok(event) => events.push(event),
                    Err(detail) => findings.push(excluded(
                        index,
                        format!("the `key` statement is unusable: {detail}"),
                    )),
                },
                _ => {}
            }
        }

        if manifests.is_empty() {
            return StructuralWalk::halted(
                "no manifest statement is anchored; a corpus always contains at least its \
                 genesis manifest",
                findings,
            );
        }
        findings.sort();
        findings.dedup();
        StructuralWalk { chain: Ok(Self { manifests, events }), findings }
    }

    /// Resolve governance **incrementally**, per adaptor §7.4.1.
    ///
    /// Walks `entries` in ascending entry-index order. The first manifest is the genesis and
    /// is tested against locally configured policy; every later `manifest` or `key` statement
    /// must verify under the key set the chain has already established *before* it can
    /// contribute anything to that key set. A statement that fails any of §7.4.1's tests is
    /// ignored for key resolution and reported in the returned findings.
    ///
    /// Returns the resolved state and the findings raised while resolving it.
    ///
    /// # Errors
    ///
    /// [`CliError::RuleFired`] when there is no usable trust anchor at all: entries out of
    /// order, no manifest, or a genesis that does not match configured policy. Everything else
    /// is a finding, because a forged governance statement is not a fork of the corpus and
    /// does not need to be reconciled with the real chain.
    pub fn resolve(
        entries: &[(u64, Value)],
        policy: &TrustPolicy,
    ) -> CliResult<(Self, Vec<Finding>)> {
        let mut resolved = Self::default();
        let mut findings = Vec::new();
        let mut previous_index: Option<u64> = None;
        let mut previous_manifest_entry_id: Option<String> = None;
        // `statement_id -> the entry index that governs it`, for the §2.1 first-wins rule over
        // EVERY governance statement — manifests and `key` statements alike, the genesis
        // included. A void entry never reaches this map: it is refused before its id is
        // claimed, so a later verifying copy of the same statement still governs.
        let mut governing_statements: BTreeMap<String, u64> = BTreeMap::new();

        for (index, envelope) in entries {
            if previous_index.is_some_and(|previous| previous >= *index) {
                return Err(CliError::RuleFired(
                    "entries must ascend by entry index; the entry index is AHL's only \
                     ordering primitive"
                        .to_owned(),
                ));
            }
            previous_index = Some(*index);

            // A structurally broken envelope is excluded, not fatal. One malformed object
            // anywhere in an enumeration would otherwise end the whole run, which hands any
            // party able to submit an entry a denial primitive over every verifier — the same
            // reasoning adaptor §7.4.1 gives for an unauthorized governance statement: it "is
            // not a fork of the corpus and does not need to be reconciled with the real
            // chain". Its **position is preserved**: the loop has already recorded this entry
            // index as the ascent watermark, so the entries after it keep the indexes the log
            // assigned, and the dense statement view fills the position with a placeholder
            // rather than closing the gap. The entry index is AHL's only ordering primitive.
            let payload = match payload_of(envelope) {
                Ok(payload) => payload,
                Err(source) => {
                    findings.push(structurally_invalid(*index, &source));
                    continue;
                }
            };
            let kind = payload.get("type").and_then(Value::as_str).unwrap_or_default();
            if !matches!(kind, "manifest" | "key") {
                continue;
            }

            // --- the genesis manifest: §7.4.1 test 4 ---------------------------------
            if resolved.manifests.is_empty() {
                if kind != "manifest" {
                    findings.push(precedes_any_manifest(*index));
                    continue;
                }
                resolved.accept_genesis(*index, envelope, payload, policy)?;
                if let Ok(id) = ahl_core::statement_id(envelope) {
                    governing_statements.insert(id, *index);
                }
                previous_manifest_entry_id = Some(entry_id(envelope));
                continue;
            }

            // --- §7.4.1 test 2: verified under the key set the chain already established --
            //
            // `resolved` holds only statements already accepted, so `producer_keys_at` is the
            // key set in force at this index under the chain BEFORE it. This is the ordering
            // the whole module exists to get right.
            if !resolved.envelope_verifies_at(envelope, *index).unwrap_or(false) {
                findings.push(Finding::new(
                    "governance-statement-not-authorized",
                    format!(
                        "the `{kind}` statement at entry index {index} does not verify under \
                         the key set in force at that index; anchoring proves bytes existed at \
                         a position and never makes an unverified governance statement \
                         effective (adaptor §7.4.1)"
                    ),
                ));
                continue;
            }

            // §2.1, over both kinds and BEFORE any state effect is applied. A later copy of
            // a statement already anchored governs nothing: for a manifest it is not the
            // version a `subject.manifest` reference resolves to, and for a `key` statement it
            // applies no effect — which is the half that bites, because a duplicate `add` after
            // a valid `retire` would otherwise put a retired key back into the set.
            let statement_id = ahl_core::statement_id(envelope).ok();
            if let Some(finding) =
                duplicate_refusal(*index, kind, statement_id.as_ref(), &governing_statements)
            {
                findings.push(finding);
                continue;
            }

            match kind {
                "manifest" => {
                    let epoch =
                        resolved.manifests.first().and_then(|(_, first)| cadence_epoch_of(first));
                    if let Some(finding) = manifest_refusal(
                        *index,
                        payload,
                        previous_manifest_entry_id.as_deref(),
                        epoch,
                    ) {
                        findings.push(finding);
                    } else {
                        record(&mut governing_statements, statement_id, *index);
                        previous_manifest_entry_id = Some(entry_id(envelope));
                        resolved.manifests.push((*index, payload.clone()));
                    }
                }
                _ => match read_key_event(*index, payload) {
                    Ok(event) => {
                        record(&mut governing_statements, statement_id, *index);
                        resolved.events.push(event);
                    }
                    Err(detail) => findings.push(Finding::new(
                        "governance-statement-not-authorized",
                        format!("the `key` statement at entry index {index} is unusable: {detail}"),
                    )),
                },
            }
        }

        if resolved.manifests.is_empty() {
            return Err(CliError::RuleFired(
                "no manifest statement authorized by the configured trust anchor is anchored; \
                 a corpus always contains at least its genesis manifest"
                    .to_owned(),
            ));
        }
        findings.sort();
        findings.dedup();
        Ok((resolved, findings))
    }

    /// §7.4.1 test 4, plus the genesis's own signature.
    ///
    /// The genesis manifest is the one statement validated by its own snapshot: there is no
    /// earlier key set to check it against, which is exactly why its entry id and key
    /// fingerprints have to come from **locally configured policy** rather than from the log.
    fn accept_genesis(
        &mut self,
        index: u64,
        envelope: &Value,
        payload: &Value,
        policy: &TrustPolicy,
    ) -> CliResult<()> {
        if index != 0 {
            return Err(CliError::RuleFired(format!(
                "the genesis manifest is anchored at entry index {index}; nothing can be \
                 governed before the corpus trust anchor, so it can only be at index 0"
            )));
        }
        if payload.get("predecessor").is_some() {
            return Err(CliError::RuleFired(
                "the genesis manifest must carry no predecessor reference".to_owned(),
            ));
        }
        // A configured anchor DIFFERING from the carried one is `unverifiable`, not `invalid`,
        // and the classification is made here rather than repaired by a caller: the material
        // may be a perfectly valid corpus that this verifier simply is not configured for, and
        // nothing about it has been disproved. The same holds for the key fingerprints, which
        // are the same trust anchor read at a finer grain.
        let anchor = entry_id(envelope);
        if anchor != policy.genesis_entry_id {
            return Err(CliError::GenesisAnchorMismatch(format!(
                "the anchored genesis manifest digests to {anchor}, local policy configures {}; \
                 this material is not the corpus this verifier is anchored to, which is a gap \
                 in local configuration rather than a defect shown in the material",
                policy.genesis_entry_id
            )));
        }
        let declared = manifest_key_ids(payload)?;
        // Compared only where local policy holds the fingerprints: `None` is "policy holds
        // none", and its absence is not a defect of the chain.
        if policy.genesis_key_ids.as_ref().is_some_and(|configured| &declared != configured) {
            return Err(CliError::GenesisAnchorMismatch(
                "the genesis manifest's producer key fingerprints are not the configured ones; \
                 the fingerprints are the same trust anchor read at a finer grain, so this is \
                 the same gap in local configuration"
                    .to_owned(),
            ));
        }

        // Provisionally in force so the genesis can be checked against its own snapshot.
        self.manifests.push((index, payload.clone()));
        if !self.envelope_verifies_at(envelope, index).unwrap_or(false) {
            self.manifests.clear();
            return Err(CliError::RuleFired(
                "the genesis manifest's own signature does not verify under the key set it \
                 declares"
                    .to_owned(),
            ));
        }
        // A genesis that does not satisfy core §7.3 is fatal rather than a finding: every
        // later version links to it, and there is then no conformant manifest version at all
        // to resolve a log key set, a cadence or an epoch against. Nothing to report about —
        // no trust anchor.
        if let Err(detail) = validate_manifest_schema(payload) {
            self.manifests.clear();
            return Err(CliError::RuleFired(format!(
                "the genesis manifest does not satisfy the normative schema of core spec §7.3: \
                 {detail}. Every member of the `log` object is REQUIRED, and the corpus trust \
                 anchor is the one manifest version no later version can repair"
            )));
        }
        Ok(())
    }

    /// The manifest version whose snapshot is in force **at** `index` — the manifest with the
    /// greatest entry index smaller than `index`, falling back to genesis at index 0, which is
    /// the one statement validated under its own snapshot.
    fn snapshot_manifest(&self, index: u64) -> Option<(u64, &Value)> {
        self.manifests
            .iter()
            .rfind(|(at, _)| *at < index)
            .or_else(|| self.manifests.first())
            .map(|(at, payload)| (*at, payload))
    }

    /// The producer key set in force at `index`, as `key_id -> pubkey`.
    #[must_use]
    pub fn producer_keys_at(&self, index: u64) -> BTreeMap<String, String> {
        let mut keys = BTreeMap::new();
        let Some((snapshot_index, manifest)) = self.snapshot_manifest(index) else {
            return keys;
        };
        // The producer key array IS the key state at the manifest's own entry index: it
        // discards the prior snapshot in full, and activity after it is decided by the `key`
        // statements below, in entry order. There is deliberately no per-key activation index
        // to honour here — a producer key object carries `{key_id, pubkey}` and nothing else —
        // so a second activation mechanism cannot compete with the snapshot. Log and witness
        // key objects are the ones that carry `valid_from_index`, and `log_keys_for` and
        // `witness_keys_for` apply it.
        for (key_id, pubkey, _) in bound_key_objects(manifest) {
            keys.insert(key_id, pubkey);
        }
        for event in self
            .events
            .iter()
            .filter(|event| event.entry_index > snapshot_index && event.entry_index <= index)
        {
            if event.added {
                keys.insert(event.key_id.clone(), event.pubkey.clone());
            } else {
                keys.remove(&event.key_id);
            }
        }
        keys
    }

    /// The manifest version active **for a checkpoint** of size `tree_size`.
    ///
    /// # Errors
    ///
    /// [`CliError::RuleFired`] when no manifest version precedes that tree size.
    pub fn active_for(&self, tree_size: u64) -> CliResult<(u64, &Value)> {
        self.manifests
            .iter()
            .rfind(|(index, _)| *index < tree_size)
            .map(|(index, payload)| (*index, payload))
            .ok_or_else(|| {
                CliError::RuleFired(format!(
                    "no manifest version is active for a checkpoint of size {tree_size}"
                ))
            })
    }

    /// The log checkpoint-signing keys **active** for a checkpoint of size `tree_size`.
    ///
    /// Two rules, and the second is the one an implementation forgets:
    ///
    /// * the key set comes from the manifest version **governing that checkpoint** — the
    ///   manifest with the greatest entry index smaller than `tree_size` ([`Self::active_for`]),
    ///   and each version's log key objects replace the prior set in full (adaptor §7.4);
    /// * within that version, a key counts only once it is **active by `valid_from_index`**
    ///   (design note §2 rule 4). Declaring a key is not the same as it being in force: a
    ///   version may name a key that starts signing later, and a checkpoint signed by it before
    ///   then is signed by a key the corpus had not yet adopted.
    ///
    /// `valid_from_index` is an *entry index*, and a checkpoint of size `tree_size` commits
    /// exactly `[0, tree_size)`. A key is therefore active for it when its activation index
    /// falls inside that range — `valid_from_index < tree_size` — which is the same boundary
    /// [`Self::active_for`] uses to choose the governing version, applied to the same scale.
    /// Returning a key that is declared but not yet active is a direct path to accepting a
    /// checkpoint no active key signed.
    ///
    /// # Errors
    ///
    /// [`CliError::RuleFired`] when the active manifest carries no usable `log.keys`.
    pub fn log_keys_for(&self, tree_size: u64) -> CliResult<BTreeMap<String, String>> {
        let (_, manifest) = self.active_for(tree_size)?;
        let log = manifest.get("log").filter(|value| value.is_object()).ok_or_else(|| {
            CliError::RuleFired("the active manifest carries no `log` object".to_owned())
        })?;
        Ok(active_key_pairs(log, tree_size).into_iter().collect())
    }

    /// The witness keys **active** for a checkpoint of size `tree_size`, across every declared
    /// witness. Each manifest version's witness key objects replace the prior set in full.
    ///
    /// Witness key objects share the §7.2 form with log key objects, `valid_from_index`
    /// included, and adaptor §7.4 states the binding rule for both together — so the activation
    /// filter of [`Self::log_keys_for`] applies here unchanged. A cosignature raises assurance,
    /// and assurance resting on a key the corpus had not yet adopted is not assurance.
    ///
    /// # Errors
    ///
    /// [`CliError::RuleFired`] when the active manifest cannot be resolved.
    pub fn witness_keys_for(&self, tree_size: u64) -> CliResult<BTreeMap<String, String>> {
        let (_, manifest) = self.active_for(tree_size)?;
        let mut keys = BTreeMap::new();
        for witness in manifest.get("witnesses").and_then(Value::as_array).unwrap_or(&Vec::new()) {
            for (key_id, pubkey) in active_key_pairs(witness, tree_size) {
                keys.insert(key_id, pubkey);
            }
        }
        Ok(keys)
    }

    /// The `log_id` the manifest version active for `tree_size` declares.
    ///
    /// # Errors
    ///
    /// [`CliError::RuleFired`] when neither spelling is present.
    pub fn log_id_for(&self, tree_size: u64) -> CliResult<String> {
        let (_, manifest) = self.active_for(tree_size)?;
        let log = manifest.get("log").filter(|value| value.is_object()).ok_or_else(|| {
            CliError::RuleFired("the active manifest carries no `log` object".to_owned())
        })?;
        log.get("log_id").and_then(Value::as_str).map(str::to_owned).ok_or_else(|| {
            CliError::RuleFired(
                "the active manifest's `log` object declares no `log_id`; core spec §7.2/§7.3 \
                 and adaptor profile §7.3 name that member and make it REQUIRED, and its value \
                 is what binds a checkpoint to the corpus's Data Tree, so there is no check to \
                 perform without it"
                    .to_owned(),
            )
        })
    }

    /// `(checkpoint_cadence, witness_grace_period)` in nanoseconds, for `tree_size`.
    ///
    /// The values are taken from the manifest version **governing that checkpoint**, never
    /// from the newest version: a later version that relaxes cadence does not retroactively
    /// make an earlier stale interval fresh (core spec §3.3, adaptor §11.3).
    ///
    /// # Errors
    ///
    /// [`CliError::Malformed`] if either duration breaks the restricted grammar of §7.3.1,
    /// [`CliError::RuleFired`] if either is absent or if cadence is not greater than zero.
    pub fn cadence_and_grace_for(&self, tree_size: u64) -> CliResult<(u64, u64)> {
        let (_, manifest) = self.active_for(tree_size)?;
        let log = manifest.get("log").filter(|value| value.is_object()).ok_or_else(|| {
            CliError::RuleFired("the active manifest carries no `log` object".to_owned())
        })?;
        let cadence = parse_time_only_duration(
            "checkpoint_cadence",
            log.get("checkpoint_cadence").and_then(Value::as_str).ok_or_else(|| {
                CliError::RuleFired(
                    "the active manifest's `log` object declares no `checkpoint_cadence`"
                        .to_owned(),
                )
            })?,
        )?;
        if cadence == 0 {
            return Err(CliError::RuleFired(
                "`checkpoint_cadence` must be greater than zero; a zero cadence states an \
                 obligation no series can satisfy"
                    .to_owned(),
            ));
        }
        let grace = parse_time_only_duration(
            "witness_grace_period",
            log.get("witness_grace_period").and_then(Value::as_str).ok_or_else(|| {
                CliError::RuleFired(
                    "the active manifest's `log` object declares no `witness_grace_period`"
                        .to_owned(),
                )
            })?,
        )?;
        Ok((cadence, grace))
    }

    /// The dataset authority key ids declared for `dataset` at `index`, if the manifest
    /// declares one.
    ///
    /// Core spec §7.2 permits authority to be omitted only for datasets with no ingestion
    /// statements in corpus scope, so `None` is a real answer and not an error here; the
    /// caller decides what an ingestion into an authority-less dataset means.
    #[must_use]
    pub fn dataset_authority(&self, index: u64, dataset: &str) -> Option<BTreeSet<String>> {
        let (_, manifest) = self.snapshot_manifest(index)?;
        let authority = manifest.get("datasets")?.get(dataset)?.get("authority")?;
        Some(
            authority
                .get("key_ids")?
                .as_array()?
                .iter()
                .filter_map(|value| value.as_str().map(str::to_owned))
                .collect(),
        )
    }

    /// The commitment mode declared for `dataset` at `index`.
    #[must_use]
    pub fn dataset_commitment_mode(&self, index: u64, dataset: &str) -> Option<String> {
        let (_, manifest) = self.snapshot_manifest(index)?;
        manifest.get("datasets")?.get(dataset)?.get("commitment_mode")?.as_str().map(str::to_owned)
    }

    /// Verify every signature on `envelope` against the producer key set in force at `index`.
    ///
    /// Core spec §2.1: an envelope is valid only if **every** entry in its `signatures` array
    /// resolves to an active key and verifies. An envelope carrying a non-verifying entry is
    /// invalid regardless of how many other entries verify. Authorization is the separate,
    /// later test of §2.3.3.
    ///
    /// # Errors
    ///
    /// [`CliError::Malformed`] if the envelope shape is wrong or a resolved key cannot be
    /// decoded.
    pub fn envelope_verifies_at(&self, envelope: &Value, index: u64) -> CliResult<bool> {
        let keys = self.producer_keys_at(index);
        ahl_core::verify_envelope(envelope, |key_id| keys.get(key_id).cloned())
            .map_err(|source| CliError::Malformed { what: "envelope", detail: source.to_string() })
    }

    /// Findings about members of every manifest version's `log` object that **this build never
    /// consults**, for a chain built by [`Self::structural_only`].
    ///
    /// Core §7.3 makes every member REQUIRED, and [`Self::resolve`] enforces the whole schema:
    /// a manifest that breaks it is **rejected** and never governs, so on a resolved chain
    /// this method has nothing left to say. It exists for the one caller that cannot adjudicate
    /// anything — topology mode, where a corpus is an unauthenticated file the operator handed
    /// over and every violation is a finding reported in full rather than a verdict.
    ///
    /// Both classes are reported there: members the `log` object omits, and key objects that
    /// cannot be read. The second matters because reading key objects leniently would drop the
    /// unreadable ones, quietly shrinking the key set rather than saying so.
    #[must_use]
    pub fn log_object_findings(&self) -> Vec<Finding> {
        let mut findings = BTreeSet::new();
        for (index, manifest) in &self.manifests {
            if let Err(detail) = validate_manifest_schema(manifest) {
                findings.insert(Finding::new(
                    "manifest-log-object-incomplete",
                    format!(
                        "the manifest at entry index {index} does not satisfy the normative \
                         schema of core spec §7.3 ({detail}); every member is REQUIRED. \
                         Nothing here is evidence, so this is reported rather than adjudicated"
                    ),
                ));
            }
        }
        findings.into_iter().collect()
    }

    /// Entry indexes of the manifest versions in the chain, ascending.
    #[must_use]
    pub fn manifest_indexes(&self) -> Vec<u64> {
        self.manifests.iter().map(|(index, _)| *index).collect()
    }
}

/// A `key` statement anchored before any manifest version, so no key set authorizes it.
fn precedes_any_manifest(index: u64) -> Finding {
    Finding::new(
        "governance-statement-not-authorized",
        format!(
            "the `key` statement at entry index {index} precedes any manifest version, so no \
             key set is in force to authorize it; it is ignored for key resolution"
        ),
    )
}

/// A structurally broken envelope, excluded from governance resolution with its position kept.
fn structurally_invalid(index: u64, source: &CliError) -> Finding {
    Finding::new(
        "entry-structurally-invalid",
        format!(
            "the entry at entry index {index} is structurally invalid and is excluded from \
             governance resolution, its position in the sequence kept: {source}"
        ),
    )
}

/// Note that `index` now governs `statement_id`, where the envelope had one to compute.
fn record(governing: &mut BTreeMap<String, u64>, statement_id: Option<String>, index: u64) {
    if let Some(id) = statement_id {
        governing.insert(id, index);
    }
}

/// The §2.1 refusal, where this envelope repeats a statement id already accepted.
///
/// "If duplicates nevertheless occur, the envelope with the smallest entry index governs and
/// later ones are void." Applied to every governance statement, of either kind, and applied
/// BEFORE the statement can have any effect — which is the whole of the rule. For a `key`
/// statement that ordering is load-bearing rather than tidy: a duplicate `add` anchored after a
/// valid `retire` would otherwise be replayed in entry order and put a retired key back into the
/// set, so a party able to re-anchor one old envelope could revive a key the corpus retired.
///
/// It is also applied before the manifest predecessor test, which would refuse a second copy
/// anyway — it links to the version active before the FIRST copy, which by then is no longer
/// active — but would refuse it as a mis-linked chain. That is not what happened, and a
/// diagnostic that is right for the wrong reason stops being right the moment the reason
/// changes.
fn duplicate_refusal(
    index: u64,
    kind: &str,
    statement_id: Option<&String>,
    governing: &BTreeMap<String, u64>,
) -> Option<Finding> {
    let first = statement_id.and_then(|id| governing.get(id))?;
    Some(Finding::new(
        "governance-statement-anchored-twice",
        format!(
            "the `{kind}` statement at entry index {index} repeats the statement id first \
             anchored at {first}; core spec §2.1 makes the smallest entry index govern and \
             voids later copies, so this one applies no effect: it contributes no key \
             transition, and it is not the version a `subject.manifest` reference resolves to"
        ),
    ))
}

/// Why a signed non-genesis manifest does not join the chain, or `None` if it does.
///
/// Two refusals, in the order the tests are stated:
///
/// * **§7.4.1 test 3** — its `predecessor` must link by entry id to the manifest version active
///   immediately before it, not merely to some earlier manifest in the log;
/// * **core §7.3** — it must satisfy the manifest schema. A version breaking it is rejected
///   rather than reported: see [`validate_manifest_schema`].
///
/// Both are refusals of *this statement*, never of the corpus: adaptor §7.4.1 is explicit that
/// such an entry "is not a fork of the corpus and does not need to be reconciled with the real
/// chain", so the version active before it simply keeps governing.
fn manifest_refusal(
    index: u64,
    payload: &Value,
    active: Option<&str>,
    genesis_epoch: Option<&str>,
) -> Option<Finding> {
    let declared = payload.get("predecessor").and_then(Value::as_str);
    if declared != active {
        return Some(Finding::new(
            "governance-statement-not-authorized",
            format!(
                "the manifest at entry index {index} references predecessor `{}`, but the \
                 version active immediately before it is `{}`; it is ignored for key resolution",
                declared.unwrap_or("<absent>"),
                active.unwrap_or("<none>")
            ),
        ));
    }
    if let Some(detail) = moved_epoch(payload, genesis_epoch) {
        return Some(Finding::new(
            "manifest-schema-invalid",
            format!(
                "the manifest at entry index {index} {detail}; core spec §7.3 and adaptor \
                 §7.3.2 declare `cadence_epoch` once, in the genesis manifest, and require \
                 every later version to repeat it unchanged, so it is rejected and does not \
                 govern. A movable epoch would let an operator re-anchor the series after the \
                 fact and erase an interval it failed to cover"
            ),
        ));
    }
    validate_manifest_schema(payload).err().map(|detail| {
        Finding::new(
            "manifest-schema-invalid",
            format!(
                "the manifest at entry index {index} does not satisfy the normative schema of \
                 core spec §7.3 ({detail}), so it is rejected and does not govern; §7.3 makes \
                 every member of the `log` object REQUIRED, and a version that omits one \
                 declares no cadence, no epoch and no key set to resolve against"
            ),
        )
    })
}

/// The `cadence_epoch` this manifest payload declares, if it declares a readable one.
fn cadence_epoch_of(payload: &Value) -> Option<&str> {
    payload.get("log")?.get("cadence_epoch")?.as_str()
}

/// Whether `payload` moves the corpus epoch away from the genesis value, and how.
///
/// Adaptor §7.3.2 fixes both halves. "Unchanged" means **by value, not by spelling**: a
/// different offset form, or added trailing zeros in the fractional part, denotes the same
/// instant and is a repetition. A rendering denoting a *different* instant is a change, and a
/// verifier MUST reject that version rather than adopting the new value or reading the change
/// as a re-anchoring. Instants are therefore compared parsed, never as strings.
fn moved_epoch(payload: &Value, genesis_epoch: Option<&str>) -> Option<String> {
    let genesis_epoch = genesis_epoch?;
    let declared = cadence_epoch_of(payload)?;
    let parse = |value: &str| {
        crate::evaluation::parse_artifact_time("cadence_epoch", value)
            .ok()
            .map(time::OffsetDateTime::unix_timestamp_nanos)
    };
    let (Some(anchored), Some(here)) = (parse(genesis_epoch), parse(declared)) else {
        // An unparseable epoch is caught by the schema check, which runs next.
        return None;
    };
    (anchored != here).then(|| {
        format!(
            "declares `cadence_epoch` `{declared}`, which is a different instant from the \
             `{genesis_epoch}` the genesis manifest anchored"
        )
    })
}

/// Validate a manifest payload against the normative schema of core spec §7.3, and the shared
/// key-object shape of §7.2.
///
/// §7.3 states the schema and then states its scope in four words: **"Every member is
/// REQUIRED."** A manifest version that omits one is not a manifest a verifier may lean on
/// while noting the omission — it declares no cadence to judge a gap by, no epoch to open the
/// series at, or no key set to resolve a checkpoint signature against. Reporting the absence
/// and carrying on is how two incompatible dialects of one manifest come to coexist, each
/// verifiable only by the implementation that wrote it, so a non-conforming manifest is
/// **rejected** here rather than reported.
///
/// The rules, each from the frozen text:
///
/// * `log` is an object, and `log_id`, `operator`, `adaptor`, `checkpoint_cadence`,
///   `cadence_epoch`, `witness_grace_period` and `keys` are all present;
/// * `log_id` and every `key_id` are `sha256:` family strings in lowercase hex (§7.3, §2);
/// * `adaptor` is `{id, hash}`, `hash` a family string;
/// * `checkpoint_cadence` and `witness_grace_period` follow the time-only duration grammar of
///   §7.3.1, and `checkpoint_cadence` is greater than zero — a zero maximum gap states an
///   obligation no published series could ever meet;
/// * `cadence_epoch` is RFC 3339;
/// * a log or witness key object is `{key_id, pubkey, valid_from_index}`, the last an entry
///   index, which is an unsigned integer because a negative or fractional value is not an
///   index into an append-only log;
/// * a producer key object is `{key_id, pubkey}` and nothing else. The two shapes differ on
///   purpose: a log or witness key may be declared valid from an index later than the
///   manifest's own, while the producer array IS the producer key state at the manifest's
///   entry index and activity after it is decided by `key` statements in entry order. A
///   per-key index there would be a second activation mechanism competing with the snapshot,
///   so a member beyond the two is a schema failure rather than a tolerated extra.
///
/// The id member is `log_id` with no alias for `id`, for the reason recorded in the module
/// documentation. What this does not fix is the encoding of `pubkey`, which core §2.3.6 leaves
/// adaptor-defined; it is decoded where it is used, under the pinned profile's rule.
///
/// The check is deliberately absent from [`Governance::structural_only`]: in topology mode
/// nothing is evidence and every violation is a finding, which is what
/// [`Governance::log_object_findings`] reports.
fn validate_manifest_schema(payload: &Value) -> Result<(), String> {
    producer_key_objects(payload)?;

    let log = payload
        .get("log")
        .filter(|value| value.is_object())
        .ok_or_else(|| "`log` is REQUIRED and must be an object".to_owned())?;

    for member in
        ["log_id", "operator", "checkpoint_cadence", "cadence_epoch", "witness_grace_period"]
    {
        if !log.get(member).is_some_and(Value::is_string) {
            return Err(format!("`log.{member}` is REQUIRED and must be a string"));
        }
    }
    family_string("log.log_id", string_of(log, "log_id"))?;

    let cadence =
        parse_time_only_duration("checkpoint_cadence", string_of(log, "checkpoint_cadence"))
            .map_err(|source| format!("`log.checkpoint_cadence`: {source}"))?;
    if cadence == 0 {
        return Err("`log.checkpoint_cadence` must be greater than zero".to_owned());
    }
    parse_time_only_duration("witness_grace_period", string_of(log, "witness_grace_period"))
        .map_err(|source| format!("`log.witness_grace_period`: {source}"))?;
    crate::evaluation::parse_artifact_time("cadence_epoch", string_of(log, "cadence_epoch"))
        .map_err(|source| format!("`log.cadence_epoch`: {source}"))?;

    let adaptor = log
        .get("adaptor")
        .filter(|value| value.is_object())
        .ok_or_else(|| "`log.adaptor` is REQUIRED and must be an object".to_owned())?;
    for member in ["id", "hash"] {
        if !adaptor.get(member).is_some_and(Value::is_string) {
            return Err(format!("`log.adaptor.{member}` is REQUIRED and must be a string"));
        }
    }
    family_string("log.adaptor.hash", string_of(adaptor, "hash"))?;

    key_objects(log, "log.keys")?;

    // Witness key objects share the §7.2 form. The member is optional — an L1 or L2 corpus
    // declares no witnesses — but a declared one is held to the same shape, so a resolved
    // chain can never drop a witness key object it could not read.
    if let Some(witnesses) = payload.get("witnesses") {
        let witnesses = witnesses
            .as_array()
            .ok_or_else(|| "`witnesses` must be an array when it is present".to_owned())?;
        for (at, witness) in witnesses.iter().enumerate() {
            if !witness.get("witness_id").is_some_and(Value::is_string) {
                return Err(format!("`witnesses[{at}].witness_id` is REQUIRED"));
            }
            key_objects(witness, &format!("witnesses[{at}].keys"))?;
        }
    }
    Ok(())
}

/// The string at `member`, for callers that have already established it is one.
fn string_of<'a>(container: &'a Value, member: &str) -> &'a str {
    container.get(member).and_then(Value::as_str).unwrap_or_default()
}

fn family_string(what: &str, value: &str) -> Result<(), String> {
    if ahl_core::parse_hash_hex(value).is_ok() {
        Ok(())
    } else {
        Err(format!("`{what}` is not a `sha256:` family string in lowercase hex"))
    }
}

/// Validate the `keys` array of `container` against the one key-object form of §7.2.
///
/// Producer, log and witness key objects share a shape, so they are checked in one place. A
/// key object that cannot be read is a rejection, never a silent omission: dropping it would
/// quietly shrink the key set a signature is resolved against, which turns a malformed
/// manifest into a *stricter-looking* one — the failure mode a verifier can least afford,
/// because it never surfaces as an error.
///
/// # The key id is recomputed, never trusted
///
/// Adaptor §7.2 makes `key_id` `"sha256:<hex of SHA-256 over the raw 32-byte public key>"` and
/// states the duty directly: "A verifier MUST recompute a key id from the public key it is
/// given and MUST reject a mismatch." §6.5 step 4 repeats it for checkpoint signatures —
/// resolve the signing key by `key_id` "recomputing the key id from the carried public key
/// rather than trusting the carried value".
///
/// Without the recomputation a `key_id -> pubkey` map is only an assertion the manifest makes
/// about itself. A manifest that files one party's public key under another party's key id
/// makes every later lookup resolve the *name* the checkpoint carries to the *key* the
/// manifest chose, and a checkpoint signed by the wrong key then verifies. Doing this once,
/// where the map is built, is what makes every consumer of the map safe.
fn key_objects(container: &Value, what: &str) -> Result<(), String> {
    for (named, object) in keys_array(container, what)? {
        bind_key(object, &named)?;
        if object.get("valid_from_index").and_then(Value::as_u64).is_none() {
            return Err(format!("`{named}.valid_from_index` is not an entry index"));
        }
    }
    Ok(())
}

/// Validate the manifest's own `keys` array: producer key objects, which carry exactly
/// `{key_id, pubkey}`.
///
/// The extra-member check is not pedantry. `valid_from_index` on a producer key object would
/// read as an activation index, and a verifier that honoured it would resolve producer
/// signatures against a key set the snapshot rule does not produce; one that ignored it would
/// accept a manifest asserting something it never evaluates. Refusing the member is what keeps
/// the snapshot the only producer-key activation mechanism.
fn producer_key_objects(payload: &Value) -> Result<(), String> {
    for (named, object) in keys_array(payload, "keys")? {
        bind_key(object, &named)?;
        let members = object.as_object().map_or(0, serde_json::Map::len);
        if members != 2 {
            return Err(format!(
                "`{named}` is a producer key object and carries exactly `key_id` and \
                 `pubkey`; a per-key activation index would compete with the manifest's own \
                 snapshot"
            ));
        }
    }
    Ok(())
}

/// One `keys` array element, paired with the name it is reported under.
type NamedKeyObject<'a> = (String, &'a Value);

/// The `keys` array of `container`, each element paired with the name it is reported under.
fn keys_array<'a>(container: &'a Value, what: &str) -> Result<Vec<NamedKeyObject<'a>>, String> {
    let keys = container
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("`{what}` is REQUIRED and must be an array"))?;
    Ok(keys.iter().enumerate().map(|(at, object)| (format!("{what}[{at}]"), object)).collect())
}

/// Read one `key_id -> pubkey` binding, **recomputing the id from the key**.
///
/// # Every such pair is read through here
///
/// Core §2.3.6 fixes the producer derivation outright — `key_id` is `sha256:` plus lowercase
/// hex SHA-256 of the raw 32-byte Ed25519 public key — and adaptor §7.2 adopts the identical
/// rule for log and witness keys, then states the duty: "A verifier MUST recompute a key id
/// from the public key it is given and MUST reject a mismatch." §6.5 step 4 repeats it where a
/// checkpoint signature resolves.
///
/// The rule is about a **pair**, not about a place. A `key_id -> pubkey` binding taken on
/// trust is only an assertion whoever wrote it makes about itself: file one party's public key
/// under another party's id and every later lookup resolves the *name* a signature carries to
/// the *key* the writer chose. That holds identically whether the pair arrives in a manifest's
/// producer, `log` or `witness` key objects or in the `key` object of a transition statement —
/// which is why both routes into the resolved key set come through this function, and why a
/// third route would have to as well.
///
/// The transition case is not the weaker one. A `key` statement is signed by a key already in
/// force, so it is exactly the primitive a compromised-but-authorized producer would reach for
/// to install a key under a name of its choosing, and the manifest chain that follows would
/// then authorize against a key the corpus never adopted.
fn bind_key(object: &Value, what: &str) -> Result<(String, String), String> {
    let key_id = object
        .get("key_id")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("`{what}.key_id` is REQUIRED"))?;
    family_string(&format!("{what}.key_id"), key_id)?;
    let pubkey = object
        .get("pubkey")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("`{what}.pubkey` is REQUIRED and must be a string"))?;
    let decoded = ahl_core::decode_pubkey(pubkey)
        .map_err(|source| format!("`{what}.pubkey` is unreadable: {source}"))?;
    let recomputed = ahl_core::sha256_hex(decoded.as_bytes());
    if recomputed != key_id {
        return Err(format!(
            "`{what}.key_id` is `{key_id}` but its `pubkey` recomputes to `{recomputed}`; core \
             §2.3.6 and adaptor §7.2 derive the id from the key and require a mismatch to be \
             rejected, so this binding is refused rather than believed"
        ));
    }
    Ok((key_id.to_owned(), pubkey.to_owned()))
}

/// Read a `key` statement's transition, or say why it is unusable.
///
/// The binding goes through [`bind_key`], so a transition installs a key only under the id its
/// own public key derives. `valid_from` is deliberately not read: core §2.3.6 makes it
/// **informative** and orders transitions by their own entry indexes, so reading it would
/// invent an ordering the specification denies it.
fn read_key_event(index: u64, payload: &Value) -> Result<KeyEvent, String> {
    let key = payload
        .get("key")
        .filter(|value| value.is_object())
        .ok_or_else(|| "it carries no `key` object".to_owned())?;
    let added = match payload.get("action").and_then(Value::as_str) {
        Some("add") => true,
        Some("retire") => false,
        other => return Err(format!("unknown key action `{}`", other.unwrap_or("<absent>"))),
    };
    let (key_id, pubkey) = bind_key(key, "the transition's `key` object")?;
    Ok(KeyEvent { entry_index: index, key_id, pubkey, added })
}

/// Every **bound** key object of `container`, as `(key_id, pubkey, valid_from_index)`.
///
/// Bound means the id was recomputed from the key by [`bind_key`], so no reader below can hand
/// out a pair that was merely asserted. Routing the readers through it rather than trusting the
/// chain to have been validated is deliberate: `Governance::resolve` does validate every
/// manifest it accepts, but [`Governance::structural_only`] validates nothing by design, and a
/// key set is exactly the wrong thing to have two construction routes into.
///
/// A key object that does not bind is left out here rather than reported, because both callers
/// already report it where reporting belongs: an authenticated chain never contains one — the
/// manifest carrying it was rejected outright — and a topology-mode chain surfaces it through
/// [`Governance::log_object_findings`], which walks the same schema. The `valid_from_index`
/// fallback has the same shape: it is REQUIRED and enforced in the schema, so only a
/// topology-mode chain can reach the default.
fn bound_key_objects(container: &Value) -> Vec<(String, String, u64)> {
    container
        .get("keys")
        .and_then(Value::as_array)
        .map(|objects| {
            objects
                .iter()
                .filter_map(|object| {
                    let (key_id, pubkey) = bind_key(object, "key object").ok()?;
                    let valid_from =
                        object.get("valid_from_index").and_then(Value::as_u64).unwrap_or(0);
                    Some((key_id, pubkey, valid_from))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `key_id -> pubkey` for the key objects of `container` that are **active** for a checkpoint
/// of size `tree_size`, by the `valid_from_index` rule of [`Governance::log_keys_for`].
fn active_key_pairs(container: &Value, tree_size: u64) -> Vec<(String, String)> {
    bound_key_objects(container)
        .into_iter()
        .filter(|(_, _, valid_from)| *valid_from < tree_size)
        .map(|(key_id, pubkey, _)| (key_id, pubkey))
        .collect()
}

fn manifest_key_ids(manifest: &Value) -> CliResult<BTreeSet<String>> {
    let keys = manifest.get("keys").and_then(Value::as_array).ok_or_else(|| {
        CliError::RuleFired("the genesis manifest carries no producer `keys` array".to_owned())
    })?;
    keys.iter()
        .map(|object| {
            object.get("key_id").and_then(Value::as_str).map(str::to_owned).ok_or_else(|| {
                CliError::RuleFired("a producer key object carries no `key_id`".to_owned())
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use ahl_core::TestKey;
    use serde_json::json;

    use super::*;

    fn producer(seed: u8) -> TestKey {
        TestKey::from_seed_hex("producer", &format!("{seed:02x}").repeat(32)).expect("seed")
    }

    /// The structural chain alone, for the many tests that only read a key set from it.
    fn structural(entries: &[(u64, Value)]) -> Governance {
        Governance::structural_only(entries).chain.expect("chain")
    }

    /// The findings a structural walk raised over `entries`, whichever way it ended.
    fn structural_findings(entries: &[(u64, Value)]) -> Vec<Finding> {
        Governance::structural_only(entries).findings
    }

    /// A `sha256:` family string, which core §7.3 requires of `log_id` and every `key_id`.
    fn family(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    /// A manifest `log` object carrying every member core §7.3 makes REQUIRED.
    fn log_object(log_id: &str, keys: &[Value]) -> Value {
        json!({
            "log_id": log_id,
            "operator": "op",
            "adaptor": { "id": "ahl-test-log-v1", "hash": family(0xbb) },
            "checkpoint_cadence": "PT1H",
            "cadence_epoch": "2026-01-01T00:00:00Z",
            "witness_grace_period": "PT15M",
            "keys": keys.to_vec(),
        })
    }

    fn genesis(log_id_member: &str) -> Value {
        let key = producer(1);
        let log_key = producer(3);
        ahl_core::envelope(
            json!({
                "type": "manifest",
                "producer": "producer-1",
                "keys": [ key.producer_key_object() ],
                "datasets": {
                    "customers": {
                        "commitment_mode": "keyed",
                        "authority": { "producer": "producer-1", "key_ids": [key.key_id()] },
                    },
                },
                "log": {
                    log_id_member: family(0xaa),
                    "operator": "op",
                    "adaptor": { "id": "ahl-test-log-v1", "hash": family(0xbb) },
                    "checkpoint_cadence": "PT1H",
                    "cadence_epoch": "2026-01-01T00:00:00Z",
                    "witness_grace_period": "PT15M",
                    "keys": [ log_key.key_object(0) ],
                },
                "witnesses": [ { "witness_id": "w1", "keys": [ producer(4).key_object(0) ] } ],
            }),
            &key,
        )
    }

    fn chain(log_id_member: &str) -> Vec<(u64, Value)> {
        vec![(0, genesis(log_id_member))]
    }

    #[test]
    fn a_missing_required_log_member_is_reported_not_adjudicated_in_topology_mode() {
        // Topology mode only: nothing there is evidence, so a violation found while walking an
        // operator-supplied file is a finding. `resolve` rejects the same manifest instead.
        let key = producer(1);
        let manifest = |log: Value| {
            ahl_core::envelope(
                json!({ "type": "manifest", "keys": [ key.producer_key_object() ], "log": log }),
                &key,
            )
        };

        let mut incomplete = log_object(&family(0xaa), &[]);
        incomplete.as_object_mut().expect("object").remove("cadence_epoch");
        let governance = structural(&[(0, manifest(incomplete))]);
        let findings = governance.log_object_findings();
        assert!(findings.iter().any(|f| f.code == "manifest-log-object-incomplete"));
        assert!(findings.iter().any(|f| f.detail.contains("cadence_epoch")), "{findings:?}");

        // A key object that cannot be read is reported too, rather than dropped: dropping one
        // shrinks the key set a signature resolves against without ever surfacing as an error.
        let broken = log_object(&family(0xaa), &[json!({ "key_id": family(0x11) })]);
        let governance = structural(&[(0, manifest(broken))]);
        let findings = governance.log_object_findings();
        assert!(findings.iter().any(|f| f.detail.contains("pubkey")), "{findings:?}");

        // A conformant one raises nothing.
        let governance = structural(&[(0, genesis("log_id"))]);
        assert!(governance.log_object_findings().is_empty());
    }

    #[test]
    fn a_non_genesis_manifest_must_link_to_the_version_active_immediately_before_it() {
        let key = producer(1);
        let first = genesis("log_id");
        let good = ahl_core::envelope(
            json!({
                "type": "manifest",
                "predecessor": entry_id(&first),
                "keys": [ key.producer_key_object() ],
                "log": log_object(&family(0xaa), &[]),
            }),
            &key,
        );
        assert!(Governance::structural_only(&[(0, first.clone()), (5, good)]).chain.is_ok());

        let wrong = ahl_core::envelope(
            json!({
                "type": "manifest",
                "predecessor": format!("sha256:{}", "77".repeat(32)),
                "keys": [ key.producer_key_object() ],
                "log": log_object(&family(0xaa), &[]),
            }),
            &key,
        );
        let findings = structural_findings(&[(0, first), (5, wrong)]);
        assert!(findings.iter().any(|f| f.code == "governance-element-excluded"), "{findings:?}");
        assert!(findings.iter().any(|f| f.detail.contains("active immediately before")));
    }

    #[test]
    fn a_genesis_manifest_carrying_a_predecessor_is_refused() {
        let key = producer(1);
        let envelope = ahl_core::envelope(
            json!({ "type": "manifest", "predecessor": family(0xaa), "keys": [],
                    "log": log_object(&family(0xaa), &[]) }),
            &key,
        );
        // Excluded and reported, so the corpus's remaining entries are still walked — and with
        // the only manifest excluded there is no chain left to resolve against, which the
        // caller reports in as many words. Both answers come back: the specific defect that
        // emptied the chain, and the general fact that nothing usable remained. Replacing the
        // first with the second would suppress a violation the walk had already established —
        // the same fault as ending the walk early, moved to the last line.
        let walk = Governance::structural_only(&[(0, envelope)]);
        let error = walk.chain.expect_err("no manifest is left");
        assert!(error.to_string().contains("no manifest statement is anchored"), "{error}");
        assert!(
            walk.findings.iter().any(|f| f.code == "governance-element-excluded"),
            "the reason the chain emptied must survive the limit: {:?}",
            walk.findings
        );
        assert!(
            walk.findings.iter().any(|f| f.detail.contains("no predecessor reference")),
            "and it must still name the rule that fired: {:?}",
            walk.findings
        );
    }

    #[test]
    fn findings_survive_the_ordering_limit_as_well_as_the_no_manifest_one() {
        // The second held error path. It can be reached after exclusions in exactly the same
        // way, so it has to carry what was already found for exactly the same reason.
        // (`corpus::load` sorts and de-duplicates before `walk` sees a corpus, so this limit is
        // reachable only through this module's own API — which is why it is pinned here rather
        // than through the binary.)
        let broken = json!({ "signatures": [] });
        let entries = vec![(0, broken), (7, genesis("log_id")), (3, genesis("log_id"))];
        let walk = Governance::structural_only(&entries);
        let error = walk.chain.expect_err("indexes do not ascend");
        assert!(error.to_string().contains("must ascend by entry index"), "{error}");
        assert!(
            walk.findings.iter().any(|f| f.code == "governance-element-excluded"),
            "the exclusion found before the limit must survive it: {:?}",
            walk.findings
        );
    }

    #[test]
    fn a_non_genesis_manifest_without_a_predecessor_is_refused() {
        let key = producer(1);
        let second = ahl_core::envelope(
            json!({ "type": "manifest", "keys": [], "log": log_object(&family(0xaa), &[]) }),
            &key,
        );
        let findings = structural_findings(&[(0, genesis("log_id")), (5, second)]);
        assert!(findings.iter().any(|f| f.detail.contains("must reference its predecessor")));
    }

    #[test]
    fn a_manifest_keys_array_is_a_snapshot_that_discards_the_prior_one() {
        let first_key = producer(1);
        let second_key = producer(2);
        let first = genesis("log_id");
        let rotation = ahl_core::envelope(
            json!({
                "type": "manifest",
                "predecessor": entry_id(&first),
                "keys": [ second_key.producer_key_object() ],
                "log": log_object(&family(0xaa), &[]),
            }),
            &first_key,
        );
        let entries = vec![(0, first), (5, rotation)];
        let governance = structural(&entries);

        // Before the rotation the first key is in force; after it, only the second.
        assert!(governance.producer_keys_at(3).contains_key(&first_key.key_id()));
        let after = governance.producer_keys_at(6);
        assert!(after.contains_key(&second_key.key_id()));
        assert!(
            !after.contains_key(&first_key.key_id()),
            "a key a later manifest omits is gone, not merged"
        );
    }

    #[test]
    fn key_statements_modify_the_snapshot_in_entry_order() {
        let first_key = producer(1);
        let added = producer(2);
        let first = genesis("log_id");
        let add = ahl_core::envelope(
            json!({ "type": "key", "action": "add", "key": added.key_object(3) }),
            &first_key,
        );
        let retire = ahl_core::envelope(
            json!({ "type": "key", "action": "retire", "key": added.key_object(3) }),
            &first_key,
        );
        let entries = vec![(0, first), (3, add), (7, retire)];
        let governance = structural(&entries);

        assert!(!governance.producer_keys_at(2).contains_key(&added.key_id()));
        assert!(governance.producer_keys_at(4).contains_key(&added.key_id()));
        assert!(!governance.producer_keys_at(8).contains_key(&added.key_id()));
    }

    #[test]
    fn an_unknown_key_action_is_refused() {
        let key = producer(1);
        let bad = ahl_core::envelope(
            json!({ "type": "key", "action": "borrow", "key": key.key_object(1) }),
            &key,
        );
        let findings = structural_findings(&[(0, genesis("log_id")), (1, bad)]);
        assert!(findings.iter().any(|f| f.detail.contains("unknown key action")), "{findings:?}");
    }

    #[test]
    fn the_manifest_governing_a_checkpoint_is_selected_by_tree_size() {
        let key = producer(1);
        let first = genesis("log_id");
        let second = ahl_core::envelope(
            json!({
                "type": "manifest",
                "predecessor": entry_id(&first),
                "keys": [ key.producer_key_object() ],
                "log": { "log_id": family(0xcc), "operator": "op",
                         "adaptor": { "id": "ahl-test-log-v1", "hash": family(0xbb) },
                         "cadence_epoch": "2026-01-01T00:00:00Z",
                         "checkpoint_cadence": "PT2H",
                         "witness_grace_period": "PT1M", "keys": [] },
            }),
            &key,
        );
        let entries = vec![(0, first), (5, second)];
        let governance = structural(&entries);

        // tree_size 5 commits [0, 5), so index 5 is NOT yet committed and genesis governs.
        assert_eq!(governance.log_id_for(5).expect("log id"), family(0xaa));
        assert_eq!(governance.log_id_for(6).expect("log id"), family(0xcc));
        assert_eq!(governance.cadence_and_grace_for(6).expect("durations").0, 7_200_000_000_000);
        assert!(governance.active_for(0).is_err());
    }

    #[test]
    fn a_prohibited_duration_component_is_rejected_rather_than_approximated() {
        let key = producer(1);
        let envelope = ahl_core::envelope(
            json!({
                "type": "manifest",
                "keys": [ key.producer_key_object() ],
                "log": { "log_id": family(0xaa), "checkpoint_cadence": "P1Y",
                         "witness_grace_period": "PT15M", "keys": [] },
            }),
            &key,
        );
        let governance = structural(&[(0, envelope)]);
        let error = governance.cadence_and_grace_for(1).expect_err("prohibited component");
        assert!(error.to_string().contains("prohibited"), "{error}");
    }

    #[test]
    fn a_zero_cadence_is_refused() {
        let key = producer(1);
        let envelope = ahl_core::envelope(
            json!({
                "type": "manifest",
                "keys": [ key.producer_key_object() ],
                "log": { "log_id": family(0xaa), "checkpoint_cadence": "PT0S",
                         "witness_grace_period": "PT15M", "keys": [] },
            }),
            &key,
        );
        let governance = structural(&[(0, envelope)]);
        assert!(governance.cadence_and_grace_for(1).is_err());
    }

    #[test]
    fn log_and_witness_keys_come_from_the_active_manifest_version() {
        let entries = chain("log_id");
        let governance = structural(&entries);
        assert!(governance.log_keys_for(1).expect("log keys").contains_key(&producer(3).key_id()));
        assert!(governance
            .witness_keys_for(1)
            .expect("witness keys")
            .contains_key(&producer(4).key_id()));
    }

    #[test]
    fn dataset_authority_and_commitment_mode_are_read_from_the_snapshot() {
        let entries = chain("log_id");
        let governance = structural(&entries);
        let authority = governance.dataset_authority(1, "customers").expect("declared");
        assert!(authority.contains(&producer(1).key_id()));
        assert_eq!(governance.dataset_commitment_mode(1, "customers").as_deref(), Some("keyed"));
        assert!(governance.dataset_authority(1, "absent").is_none());
    }

    #[test]
    fn envelope_signatures_are_verified_against_the_key_set_at_their_index() {
        let key = producer(1);
        let stranger = producer(9);
        let entries = chain("log_id");
        let governance = structural(&entries);

        let good = ahl_core::envelope(json!({ "type": "ingestion" }), &key);
        assert!(governance.envelope_verifies_at(&good, 1).expect("well-formed"));
        let bad = ahl_core::envelope(json!({ "type": "ingestion" }), &stranger);
        assert!(!governance.envelope_verifies_at(&bad, 1).expect("well-formed"));
    }

    #[test]
    fn entries_must_ascend_and_a_corpus_must_carry_a_manifest() {
        let entries = vec![(5, genesis("log_id")), (1, genesis("log_id"))];
        assert!(Governance::structural_only(&entries).chain.is_err());

        let key = producer(1);
        let ingestion = ahl_core::envelope(json!({ "type": "ingestion" }), &key);
        assert!(Governance::structural_only(&[(0, ingestion)]).chain.is_err());
    }

    #[test]
    fn a_typeless_or_payloadless_entry_is_refused() {
        // Each is excluded and reported rather than ending the walk; with nothing else in the
        // corpus, what remains is a chain with no manifest, which the caller reports.
        for broken in [json!({ "signatures": [] }), json!({ "payload": { "a": 1 } })] {
            let error =
                Governance::structural_only(&[(0, broken)]).chain.expect_err("nothing usable");
            assert!(error.to_string().contains("no manifest statement is anchored"), "{error}");
        }
        let findings = structural_findings(&[(0, genesis("log_id")), (1, json!({ "a": 1 }))]);
        assert!(findings.iter().any(|f| f.code == "governance-element-excluded"), "{findings:?}");
    }

    // -- adaptor §7.4.1: governance is not self-authorizing ---------------------------

    fn policy_for(entries: &[(u64, Value)], key: &TestKey) -> TrustPolicy {
        TrustPolicy {
            genesis_entry_id: entry_id(&entries[0].1),
            genesis_key_ids: Some(BTreeSet::from([key.key_id()])),
            ..TrustPolicy::default()
        }
    }

    /// A manifest a hostile party anchored: well-formed, at a real index, signed by a key the
    /// corpus never adopted, naming attacker log keys.
    fn forged_manifest(predecessor: &Value, attacker: &TestKey, log_key: &TestKey) -> Value {
        ahl_core::envelope(
            json!({
                "type": "manifest",
                "predecessor": entry_id(predecessor),
                "keys": [ attacker.producer_key_object() ],
                "log": log_object(&family(0xaa), &[ log_key.key_object(0) ]),
            }),
            attacker,
        )
    }

    #[test]
    fn a_forged_later_manifest_never_contributes_to_the_resolved_key_set() {
        // The blocker this module was rewritten for. A hostile mirror serves a recomputable
        // tree containing the genuine pinned genesis manifest PLUS a forged later manifest
        // naming attacker log keys. If the chain were collected first and checked afterwards,
        // a checkpoint signed by those keys would authenticate.
        let honest = producer(1);
        let attacker = producer(9);
        let attacker_log_key = producer(8);
        let first = genesis("log_id");
        let forged = forged_manifest(&first, &attacker, &attacker_log_key);
        let entries = vec![(0, first), (5, forged)];

        let (resolved, findings) =
            Governance::resolve(&entries, &policy_for(&entries, &honest)).expect("anchor holds");

        assert_eq!(
            resolved.manifest_indexes(),
            vec![0],
            "the forged manifest must not join the chain"
        );
        assert!(findings.iter().any(|f| f.code == "governance-statement-not-authorized"));
        // And the attacker's log key is not resolvable for any checkpoint.
        let log_keys = resolved.log_keys_for(9).expect("genesis governs");
        assert!(!log_keys.contains_key(&attacker_log_key.key_id()));
        assert!(log_keys.contains_key(&producer(3).key_id()), "the genuine log key still is");
    }

    #[test]
    fn a_forged_key_statement_never_adds_a_producer_key() {
        let honest = producer(1);
        let attacker = producer(9);
        let first = genesis("log_id");
        let forged = ahl_core::envelope(
            json!({ "type": "key", "action": "add", "key": attacker.key_object(3) }),
            &attacker,
        );
        let entries = vec![(0, first), (3, forged)];
        let (resolved, findings) =
            Governance::resolve(&entries, &policy_for(&entries, &honest)).expect("anchor holds");
        assert!(!resolved.producer_keys_at(4).contains_key(&attacker.key_id()));
        assert!(findings.iter().any(|f| f.code == "governance-statement-not-authorized"));
    }

    #[test]
    fn a_key_statement_before_any_manifest_is_not_governance() {
        let honest = producer(1);
        let attacker = producer(9);
        let early = ahl_core::envelope(
            json!({ "type": "key", "action": "add", "key": attacker.key_object(0) }),
            &attacker,
        );
        let first = genesis("log_id");
        let entries = vec![(0, early), (1, first.clone())];
        let policy = TrustPolicy {
            genesis_entry_id: entry_id(&first),
            genesis_key_ids: Some(BTreeSet::from([honest.key_id()])),
            ..TrustPolicy::default()
        };
        // The genesis is not at index 0 here, so there is no usable anchor at all.
        assert!(Governance::resolve(&entries, &policy).is_err());
    }

    #[test]
    fn a_genuine_rotation_signed_by_the_key_set_before_it_is_accepted() {
        // The other direction: the incremental rule must not reject an honest chain.
        let honest = producer(1);
        let rotated = producer(2);
        let first = genesis("log_id");
        let second = ahl_core::envelope(
            json!({
                "type": "manifest",
                "predecessor": entry_id(&first),
                "keys": [ rotated.producer_key_object() ],
                "log": log_object(&family(0xcc), &[ producer(3).key_object(0) ]),
            }),
            &honest,
        );
        let entries = vec![(0, first), (5, second)];
        let (resolved, findings) =
            Governance::resolve(&entries, &policy_for(&entries, &honest)).expect("anchor holds");
        assert_eq!(resolved.manifest_indexes(), vec![0, 5]);
        assert!(findings.iter().all(|f| f.code != "governance-statement-not-authorized"));
        assert_eq!(resolved.log_id_for(6).expect("log id"), family(0xcc));
        // And after the rotation the old producer key is gone.
        assert!(!resolved.producer_keys_at(6).contains_key(&honest.key_id()));
    }

    #[test]
    fn a_manifest_linking_past_the_active_version_is_ignored_for_key_resolution() {
        let honest = producer(1);
        let first = genesis("log_id");
        let second = ahl_core::envelope(
            json!({
                "type": "manifest",
                "predecessor": entry_id(&first),
                "keys": [ honest.producer_key_object() ],
                "log": log_object(&family(0xcc), &[]),
            }),
            &honest,
        );
        // Links to genesis rather than to the version active immediately before it.
        let third = ahl_core::envelope(
            json!({
                "type": "manifest",
                "predecessor": entry_id(&first),
                "keys": [ honest.producer_key_object() ],
                "log": log_object(&family(0xdd), &[]),
            }),
            &honest,
        );
        let entries = vec![(0, first), (5, second), (9, third)];
        let (resolved, findings) =
            Governance::resolve(&entries, &policy_for(&entries, &honest)).expect("anchor holds");
        assert_eq!(resolved.manifest_indexes(), vec![0, 5]);
        assert!(findings.iter().any(|f| f.detail.contains("active immediately before")));
    }

    // -- core §7.3: the manifest schema is checked, not reported -----------------------

    #[test]
    fn a_signed_manifest_that_breaks_the_7_3_schema_is_rejected_rather_than_reported() {
        // §7.3 states the schema and then states its scope: "Every member is REQUIRED." A
        // version that omits one declares no cadence to judge a gap by, no epoch to open the
        // series at, or no key set to resolve a checkpoint signature against — so accepting it
        // while noting the omission lets it govern anyway, and the note is all a consumer ever
        // sees. It is signed by the key set in force at its index, so §7.4.1 does not catch it.
        let honest = producer(1);
        let first = genesis("log_id");
        for missing in ["operator", "adaptor", "cadence_epoch", "witness_grace_period", "keys"] {
            let mut log = log_object(&family(0xcc), &[]);
            log.as_object_mut().expect("object").remove(missing);
            let second = ahl_core::envelope(
                json!({
                    "type": "manifest",
                    "predecessor": entry_id(&first),
                    "keys": [ honest.producer_key_object() ],
                    "log": log,
                }),
                &honest,
            );
            let entries = vec![(0, first.clone()), (5, second)];
            let (resolved, findings) =
                Governance::resolve(&entries, &policy_for(&entries, &honest))
                    .expect("the anchor still holds");
            assert_eq!(
                resolved.manifest_indexes(),
                vec![0],
                "a manifest omitting `log.{missing}` must not govern"
            );
            assert!(
                findings.iter().any(|f| f.code == "manifest-schema-invalid"),
                "omitting `log.{missing}` went unreported: {findings:?}"
            );
            // The version before it keeps governing, so nothing is silently re-pointed.
            assert_eq!(resolved.log_id_for(9).expect("log id"), family(0xaa));
        }
    }

    #[test]
    fn a_key_object_that_cannot_be_read_makes_the_manifest_non_conforming_never_a_shorter_set() {
        // Reading key objects leniently drops the ones that cannot be read, which quietly
        // shrinks the key set a signature is resolved against. That turns a malformed manifest
        // into a stricter-looking one — the failure mode a verifier can least afford, because
        // it never surfaces as an error.
        let honest = producer(1);
        let first = genesis("log_id");
        let broken = [
            json!({ "pubkey": producer(3).pubkey(), "valid_from_index": 0 }),
            json!({ "key_id": producer(3).key_id(), "valid_from_index": 0 }),
            json!({ "key_id": producer(3).key_id(), "pubkey": producer(3).pubkey() }),
            json!({ "key_id": "sha256:aa", "pubkey": producer(3).pubkey(),
                    "valid_from_index": 0 }),
            json!({ "key_id": producer(3).key_id(), "pubkey": producer(3).pubkey(),
                    "valid_from_index": -1 }),
        ];
        for object in broken {
            let second = ahl_core::envelope(
                json!({
                    "type": "manifest",
                    "predecessor": entry_id(&first),
                    "keys": [ honest.producer_key_object() ],
                    "log": log_object(&family(0xcc), std::slice::from_ref(&object)),
                }),
                &honest,
            );
            let entries = vec![(0, first.clone()), (5, second)];
            let (resolved, findings) =
                Governance::resolve(&entries, &policy_for(&entries, &honest))
                    .expect("the anchor still holds");
            assert_eq!(resolved.manifest_indexes(), vec![0], "rejected, not silently trimmed");
            assert!(findings.iter().any(|f| f.code == "manifest-schema-invalid"), "{object}");
        }
    }

    #[test]
    fn the_key_id_derivation_is_the_family_one_and_this_crate_does_not_own_a_second_copy() {
        // A cross-crate binding vector. This crate re-derives governance rules from the frozen
        // text because `ahl-core` resolves governance only inside `verify_receipt`, from the
        // chain a receipt carries, and exposes no entry point for a live enumeration. A copy
        // can drift, and two rules already had; this test ties the half that is a *derivation*
        // to the family's own.
        //
        // The left-hand side is what this module recomputes when it validates a key object.
        // The right-hand side is `ahl-core`'s `TestKey::key_id`, which runs through
        // `atl_core::compute_key_id` — the derivation adaptor §7.2 names. If the family
        // changes it, this fails here rather than leaving the client resolving key ids nobody
        // else computes.
        for seed in [1_u8, 3, 8] {
            let key = producer(seed);
            let decoded = ahl_core::decode_pubkey(&key.pubkey()).expect("family encoding");
            assert_eq!(
                ahl_core::sha256_hex(decoded.as_bytes()),
                key.key_id(),
                "the key id this crate recomputes must be the family derivation"
            );
        }

        // And the encodings the derivation rests on are the ones §7.2 fixes.
        let key = producer(1);
        assert!(key.pubkey().starts_with("base64:"), "{}", key.pubkey());
        assert!(key.key_id().starts_with("sha256:"), "{}", key.key_id());
        assert_eq!(key.key_id().len(), "sha256:".len() + 64);
    }

    #[test]
    fn a_key_id_is_recomputed_from_its_public_key_and_a_mismatch_is_rejected() {
        // Adaptor §7.2: "A verifier MUST recompute a key id from the public key it is given and
        // MUST reject a mismatch." §6.5 step 4 repeats it where a checkpoint signature resolves.
        // The pinned genesis here is correctly signed and otherwise conformant; what it does is
        // file one party's public key under another party's key id. Without the recomputation
        // the map resolves the name a checkpoint carries to the key the manifest chose, and a
        // checkpoint signed by that key verifies under a `key_id` its holder never owned.
        let honest = producer(1);
        let borrowed_id = producer(8).key_id();
        let genesis = ahl_core::envelope(
            json!({
                "type": "manifest",
                "keys": [ honest.producer_key_object() ],
                "log": log_object(
                    &family(0xaa),
                    &[json!({
                        "key_id": borrowed_id,
                        "pubkey": producer(3).pubkey(),
                        "valid_from_index": 0,
                    })],
                ),
            }),
            &honest,
        );
        let entries = vec![(0, genesis)];
        let error = Governance::resolve(&entries, &policy_for(&entries, &honest))
            .expect_err("the id does not recompute");
        assert!(error.to_string().contains("recomputes to"), "{error}");
        assert!(error.to_string().contains(&producer(3).key_id()), "{error}");

        // Filed under its own id, the same object is fine.
        let genesis = ahl_core::envelope(
            json!({
                "type": "manifest",
                "keys": [ honest.producer_key_object() ],
                "log": log_object(&family(0xaa), &[producer(3).key_object(0)]),
            }),
            &honest,
        );
        let entries = vec![(0, genesis)];
        let (resolved, _) =
            Governance::resolve(&entries, &policy_for(&entries, &honest)).expect("conformant");
        assert!(resolved.log_keys_for(1).expect("log keys").contains_key(&producer(3).key_id()));
    }

    #[test]
    fn a_log_key_counts_only_once_it_is_active_by_its_valid_from_index() {
        // Design note §2 rule 4: the signing key must be in the governing version's `log.keys`
        // **and active by `valid_from_index`**. `valid_from_index` is an entry index and a
        // checkpoint of size `n` commits exactly `[0, n)`, so a key activating at an index the
        // checkpoint does not commit has not been adopted yet.
        let honest = producer(1);
        let genesis = ahl_core::envelope(
            json!({
                "type": "manifest",
                "keys": [ honest.producer_key_object() ],
                "log": log_object(
                    &family(0xaa),
                    &[
                        json!({ "key_id": producer(3).key_id(), "pubkey": producer(3).pubkey(),
                                "valid_from_index": 0 }),
                        json!({ "key_id": producer(4).key_id(), "pubkey": producer(4).pubkey(),
                                "valid_from_index": 14 }),
                    ],
                ),
                "witnesses": [ {
                    "witness_id": "w1",
                    "keys": [ json!({ "key_id": producer(5).key_id(),
                                      "pubkey": producer(5).pubkey(),
                                      "valid_from_index": 14 }) ],
                } ],
            }),
            &honest,
        );
        let entries = vec![(0, genesis)];
        let (resolved, _) =
            Governance::resolve(&entries, &policy_for(&entries, &honest)).expect("conformant");

        let at_eight = resolved.log_keys_for(8).expect("log keys");
        assert!(at_eight.contains_key(&producer(3).key_id()), "the active key is in force");
        assert!(
            !at_eight.contains_key(&producer(4).key_id()),
            "a key activating at entry index 14 is not in force for a checkpoint of size 8"
        );
        let at_thirteen = resolved.log_keys_for(13).expect("log keys");
        assert!(
            !at_thirteen.contains_key(&producer(4).key_id()),
            "nor for one of size 13, which commits [0, 13) and never reaches index 14"
        );
        // It comes into force for the first checkpoint that commits its activation index.
        assert!(resolved.log_keys_for(15).expect("log keys").contains_key(&producer(4).key_id()));
        assert!(!resolved.log_keys_for(14).expect("log keys").contains_key(&producer(4).key_id()));

        // Witness key objects share the §7.2 form, and adaptor §7.4 binds both the same way.
        assert!(!resolved
            .witness_keys_for(13)
            .expect("witness keys")
            .contains_key(&producer(5).key_id()));
        assert!(resolved
            .witness_keys_for(15)
            .expect("witness keys")
            .contains_key(&producer(5).key_id()));
    }

    #[test]
    fn a_version_anchored_twice_governs_once_and_says_why() {
        // Core spec §2.1: "the envelope with the smallest entry index governs and later ones
        // are void". The conformance corpus anchors one manifest version under three envelopes
        // — one governing, one that verifies and repeats it, one that does not verify at all —
        // and only the first may govern. The predecessor test would refuse the second copy too,
        // for a reason that is not what happened, so the rule is applied where it belongs and
        // the finding says which entry governs instead.
        let fixture = crate::testing::MirrorFixture::conformance()
            .expect("the conformance corpus publishes the key seeds the fixture signs with");
        let entries: Vec<(u64, Value)> = fixture
            .corpus_entries()
            .into_iter()
            .enumerate()
            .filter_map(|(at, envelope)| Some((u64::try_from(at).ok()?, envelope)))
            .collect();
        let (resolved, findings) =
            Governance::resolve(&entries, fixture.trust_policy()).expect("the anchor holds");

        let duplicates: Vec<&Finding> = findings
            .iter()
            .filter(|finding| finding.code == "governance-statement-anchored-twice")
            .collect();
        assert_eq!(duplicates.len(), 1, "one verifying second copy: {findings:?}");
        assert!(
            duplicates[0].detail.contains("§2.1")
                && duplicates[0].detail.contains("applies no effect"),
            "the reason is the duplicate rule, not the predecessor link: {}",
            duplicates[0].detail
        );
        assert!(duplicates[0].detail.contains("`manifest` statement"), "{}", duplicates[0].detail);

        // And exactly one entry governs that version: the copies are not in the chain.
        let governing = resolved.manifest_indexes();
        assert!(
            governing.len() >= 3,
            "the corpus rotates governance more than once: {governing:?}"
        );
        let mut ascending = governing.clone();
        ascending.dedup();
        assert_eq!(ascending, governing, "each version appears once: {governing:?}");
    }

    #[test]
    fn a_duplicate_key_statement_applies_no_effect_and_never_revives_a_retired_key() {
        // Core spec §2.1: "the envelope with the smallest entry index governs and later ones are
        // void." For a `key` statement that is not bookkeeping. Events are replayed in entry
        // order, so a duplicate `add` anchored AFTER a valid `retire` would be applied a second
        // time and put the retired key back into the producer set — handing anyone able to
        // re-anchor one old envelope the power to revive a key the corpus retired.
        let honest = producer(1);
        let revived = producer(2);
        let genesis = ahl_core::envelope(
            json!({
                "type": "manifest",
                "keys": [ honest.producer_key_object() ],
                "log": log_object(&family(0xaa), &[producer(3).key_object(0)]),
            }),
            &honest,
        );
        let add = ahl_core::envelope(
            json!({ "type": "key", "action": "add", "key": revived.key_object(10) }),
            &honest,
        );
        let retire = ahl_core::envelope(
            json!({ "type": "key", "action": "retire", "key": revived.key_object(10) }),
            &honest,
        );
        // Byte-identical to the `add`, so it carries the same statement id.
        let entries = vec![(0, genesis), (10, add.clone()), (20, retire), (30, add)];
        let policy = TrustPolicy {
            genesis_entry_id: entry_id(&entries[0].1),
            genesis_key_ids: Some(BTreeSet::from([honest.key_id()])),
            ..TrustPolicy::default()
        };
        let (resolved, findings) = Governance::resolve(&entries, &policy).expect("anchor holds");

        assert!(
            resolved.producer_keys_at(15).contains_key(&revived.key_id()),
            "the add governs from its own index"
        );
        assert!(
            !resolved.producer_keys_at(25).contains_key(&revived.key_id()),
            "the retire takes it out again"
        );
        assert!(
            !resolved.producer_keys_at(35).contains_key(&revived.key_id()),
            "and a duplicate of the add applies no effect: the key stays retired"
        );
        let duplicates: Vec<&Finding> = findings
            .iter()
            .filter(|finding| finding.code == "governance-statement-anchored-twice")
            .collect();
        assert_eq!(duplicates.len(), 1, "the duplicate is reported, not silently dropped");
        assert!(duplicates[0].detail.contains("`key` statement"), "{}", duplicates[0].detail);
        assert!(duplicates[0].detail.contains("30"), "{}", duplicates[0].detail);
    }

    #[test]
    fn a_second_copy_of_the_genesis_manifest_is_void_under_the_duplicate_rule() {
        // The genesis is accepted on its own path — it is the one manifest checked against
        // local policy rather than against the chain — so it has to claim its statement id
        // there too. Otherwise its duplicate falls through to the predecessor test and is
        // refused as a mis-linked chain, which is not what happened to it.
        let honest = producer(1);
        let genesis = ahl_core::envelope(
            json!({
                "type": "manifest",
                "keys": [ honest.producer_key_object() ],
                "log": log_object(&family(0xaa), &[producer(3).key_object(0)]),
            }),
            &honest,
        );
        let entries = vec![(0, genesis.clone()), (7, genesis)];
        let policy = TrustPolicy {
            genesis_entry_id: entry_id(&entries[0].1),
            genesis_key_ids: Some(BTreeSet::from([honest.key_id()])),
            ..TrustPolicy::default()
        };
        let (resolved, findings) = Governance::resolve(&entries, &policy).expect("anchor holds");

        assert_eq!(resolved.manifest_indexes(), vec![0], "the genesis governs once");
        let duplicates: Vec<&Finding> = findings
            .iter()
            .filter(|finding| finding.code == "governance-statement-anchored-twice")
            .collect();
        assert_eq!(duplicates.len(), 1, "{findings:?}");
        assert!(
            duplicates[0].detail.contains("first anchored at 0"),
            "the entry that governs is named: {}",
            duplicates[0].detail
        );
    }

    #[test]
    fn a_configured_anchor_that_differs_is_unverifiable_at_its_source() {
        // I-D §7.5.1 4a and the note's rule 1: a configured anchor differing from the carried
        // one is `unverifiable`. Classified here rather than repaired downstream, so a caller
        // that does not pass the result through a remote-candidate wrapper still gets the right
        // answer, and so the two paths cannot drift apart.
        let honest = producer(1);
        let entries = chain("log_id");
        let anchored = policy_for(&entries, &honest);

        let mut elsewhere = TrustPolicy {
            genesis_entry_id: format!("sha256:{}", "99".repeat(32)),
            ..anchored.clone()
        };
        let error = Governance::resolve(&entries, &elsewhere).expect_err("another corpus");
        assert!(matches!(error, CliError::GenesisAnchorMismatch(_)), "{error}");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
        assert_eq!(error.reason_code(), "genesis-anchor-mismatch");

        // The fingerprints are the same anchor at a finer grain, and answer the same way.
        elsewhere.genesis_entry_id = anchored.genesis_entry_id;
        elsewhere.genesis_key_ids = Some(BTreeSet::from([format!("sha256:{}", "88".repeat(32))]));
        let error = Governance::resolve(&entries, &elsewhere).expect_err("other fingerprints");
        assert!(matches!(error, CliError::GenesisAnchorMismatch(_)), "{error}");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);

        // A defect in the anchor's own material is still a defect: only the CONFIGURATION gap
        // moved, not the adjudication of what the chain carries.
        let broken = ahl_core::envelope(
            json!({ "type": "manifest", "keys": [], "log": log_object(&family(0xaa), &[]) }),
            &honest,
        );
        let entries = vec![(0, broken)];
        let policy = TrustPolicy {
            genesis_entry_id: entry_id(&entries[0].1),
            genesis_key_ids: None,
            ..TrustPolicy::default()
        };
        let error = Governance::resolve(&entries, &policy).expect_err("schema failure");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Invalid, "{error}");
    }

    #[test]
    fn a_producer_key_snapshot_is_the_whole_state_and_carries_no_per_key_activation_index() {
        // The producer array IS the key state at the manifest's entry index, so every member
        // of it is in force from that index on. A per-key activation index there would be a
        // second activation mechanism competing with the snapshot, so carrying one is a schema
        // failure rather than a member a verifier may quietly honour or quietly ignore —
        // either reading resolves a producer signature against a key set the snapshot rule
        // does not produce.
        let honest = producer(1);
        let later = producer(2);
        let manifest = |keys: Value| {
            ahl_core::envelope(
                json!({
                    "type": "manifest",
                    "keys": keys,
                    "log": log_object(&family(0xaa), &[producer(3).key_object(0)]),
                }),
                &honest,
            )
        };

        let entries =
            vec![(0, manifest(json!([honest.producer_key_object(), later.producer_key_object()])))];
        let policy = TrustPolicy {
            genesis_entry_id: entry_id(&entries[0].1),
            genesis_key_ids: Some(BTreeSet::from([honest.key_id(), later.key_id()])),
            ..TrustPolicy::default()
        };
        let (resolved, _) = Governance::resolve(&entries, &policy).expect("conformant");
        for index in [0, 6, 7] {
            assert!(
                resolved.producer_keys_at(index).contains_key(&later.key_id()),
                "every member of the snapshot is in force from the manifest's index on"
            );
        }

        // The same manifest with an activation index on a producer key object is refused, and
        // the trust anchor is the one version no later one can repair.
        let with_index = vec![(0, manifest(json!([honest.key_object(0)])))];
        let policy = TrustPolicy {
            genesis_entry_id: entry_id(&with_index[0].1),
            genesis_key_ids: Some(BTreeSet::from([honest.key_id()])),
            ..TrustPolicy::default()
        };
        let error = Governance::resolve(&with_index, &policy).expect_err("schema failure");
        assert!(error.to_string().contains("producer key object"), "{error}");
    }

    #[test]
    fn a_later_manifest_version_that_moves_the_cadence_epoch_never_governs() {
        // Core §7.3 and adaptor §7.3.2: the epoch is declared once, by the genesis manifest,
        // and repeated unchanged by every later version. A movable epoch would let an operator
        // re-anchor the series after the fact and erase an interval it failed to cover.
        let honest = producer(1);
        let first = genesis("log_id");
        let rotation = |epoch: &str| {
            let mut log = log_object(&family(0xcc), &[producer(3).key_object(0)]);
            log["cadence_epoch"] = json!(epoch);
            ahl_core::envelope(
                json!({
                    "type": "manifest",
                    "predecessor": entry_id(&first),
                    "keys": [ honest.producer_key_object() ],
                    "log": log,
                }),
                &honest,
            )
        };

        let entries = vec![(0, first.clone()), (5, rotation("2026-01-01T01:00:00Z"))];
        let (resolved, findings) =
            Governance::resolve(&entries, &policy_for(&entries, &honest)).expect("anchor holds");
        assert_eq!(resolved.manifest_indexes(), vec![0], "a moved epoch must not govern");
        assert!(findings.iter().any(|f| f.code == "manifest-schema-invalid"), "{findings:?}");
        assert!(findings.iter().any(|f| f.detail.contains("different instant")), "{findings:?}");
        // The version before it keeps governing, so nothing is silently re-pointed.
        assert_eq!(resolved.log_id_for(9).expect("log id"), family(0xaa));

        // "Unchanged" is by value, not by spelling: another rendering of the same instant is a
        // repetition, and adopting it is not a re-anchoring (adaptor §7.3.2).
        let entries = vec![(0, first.clone()), (5, rotation("2026-01-01T00:00:00.000+00:00"))];
        let (resolved, _) =
            Governance::resolve(&entries, &policy_for(&entries, &honest)).expect("anchor holds");
        assert_eq!(resolved.manifest_indexes(), vec![0, 5], "the same instant, respelled");
    }

    #[test]
    fn a_genesis_that_breaks_the_7_3_schema_is_fatal_because_no_later_version_can_repair_it() {
        let honest = producer(1);
        let mut payload = json!({
            "type": "manifest",
            "keys": [ honest.producer_key_object() ],
            "log": log_object(&family(0xaa), &[ producer(3).key_object(0) ]),
        });
        payload["log"]["cadence_epoch"] = json!("not-a-timestamp");
        let entries = vec![(0, ahl_core::envelope(payload, &honest))];
        let error = Governance::resolve(&entries, &policy_for(&entries, &honest))
            .expect_err("no conformant trust anchor");
        assert!(error.to_string().contains("§7.3"), "{error}");
        assert!(error.to_string().contains("cadence_epoch"), "{error}");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Invalid);
    }

    #[test]
    fn a_prohibited_duration_in_a_manifest_is_a_schema_rejection_not_a_later_surprise() {
        let honest = producer(1);
        let first = genesis("log_id");
        let mut log = log_object(&family(0xcc), &[]);
        log["checkpoint_cadence"] = json!("P1Y");
        let second = ahl_core::envelope(
            json!({
                "type": "manifest",
                "predecessor": entry_id(&first),
                "keys": [ honest.producer_key_object() ],
                "log": log,
            }),
            &honest,
        );
        let entries = vec![(0, first), (5, second)];
        let (resolved, findings) =
            Governance::resolve(&entries, &policy_for(&entries, &honest)).expect("anchor holds");
        assert_eq!(resolved.manifest_indexes(), vec![0]);
        assert!(findings.iter().any(|f| f.detail.contains("prohibited")), "{findings:?}");
    }

    #[test]
    fn one_structurally_broken_envelope_is_excluded_and_the_walk_continues() {
        // A malformed object anywhere in an enumeration would otherwise end the whole run,
        // which hands any party able to submit an entry a denial primitive over every verifier
        // — the same reasoning adaptor §7.4.1 gives for an unauthorized governance statement.
        // Its position is kept: the entry index is AHL's only ordering primitive.
        let honest = producer(1);
        let first = genesis("log_id");
        let rotation = ahl_core::envelope(
            json!({
                "type": "manifest",
                "predecessor": entry_id(&first),
                "keys": [ producer(2).producer_key_object() ],
                "log": log_object(&family(0xcc), &[ producer(3).key_object(0) ]),
            }),
            &honest,
        );
        for broken in [
            json!({ "signatures": [] }),
            json!({ "payload": "not an object", "signatures": [] }),
            json!({ "payload": [], "signatures": [] }),
        ] {
            let entries = vec![(0, first.clone()), (4, broken.clone()), (9, rotation.clone())];
            let (resolved, findings) =
                Governance::resolve(&entries, &policy_for(&entries, &honest))
                    .expect("one broken envelope must not end the run");
            assert_eq!(
                resolved.manifest_indexes(),
                vec![0, 9],
                "the entries after the broken one keep the indexes the log assigned"
            );
            assert!(
                findings.iter().any(|f| f.code == "entry-structurally-invalid"),
                "the exclusion must be reported, never silent: {findings:?}"
            );
            // The rotation the broken entry preceded still takes effect at its own index.
            assert!(resolved.producer_keys_at(10).contains_key(&producer(2).key_id()));
        }
    }

    #[test]
    fn a_genesis_that_is_not_the_configured_anchor_is_fatal_not_a_finding() {
        let honest = producer(1);
        let entries = vec![(0, genesis("log_id"))];
        let mut policy = policy_for(&entries, &honest);
        policy.genesis_entry_id = format!("sha256:{}", "99".repeat(32));
        let error = Governance::resolve(&entries, &policy).expect_err("no trust anchor");
        assert!(error.to_string().contains("local policy configures"), "{error}");

        let mut policy = policy_for(&entries, &honest);
        policy.genesis_key_ids = Some(BTreeSet::from([format!("sha256:{}", "88".repeat(32))]));
        assert!(Governance::resolve(&entries, &policy).is_err());
    }

    #[test]
    fn a_genesis_whose_own_signature_does_not_verify_is_fatal() {
        let honest = producer(1);
        let stranger = producer(9);
        // Declares the honest key set but is signed by someone else.
        let forged = ahl_core::envelope(
            json!({
                "type": "manifest",
                "keys": [ honest.producer_key_object() ],
                "log": log_object(&family(0xaa), &[]),
            }),
            &stranger,
        );
        let entries = vec![(0, forged)];
        let policy = policy_for(&entries, &honest);
        let error = Governance::resolve(&entries, &policy).expect_err("self-signature");
        assert!(error.to_string().contains("own signature"), "{error}");
    }

    #[test]
    fn the_resolved_chain_is_never_the_structural_one() {
        // A regression guard for the inversion itself: the structural walk accepts the forged
        // manifest (it checks no signatures, by design and by name), the resolved one does not.
        let honest = producer(1);
        let attacker = producer(9);
        let first = genesis("log_id");
        let forged = forged_manifest(&first, &attacker, &producer(8));
        let entries = vec![(0, first), (5, forged)];

        let structural = structural(&entries);
        assert_eq!(structural.manifest_indexes(), vec![0, 5]);

        let (resolved, _) =
            Governance::resolve(&entries, &policy_for(&entries, &honest)).expect("anchor holds");
        assert_eq!(resolved.manifest_indexes(), vec![0]);
        assert_ne!(structural.manifest_indexes(), resolved.manifest_indexes());
    }

    #[test]
    fn a_log_object_without_the_specification_spelling_has_no_check_to_perform() {
        let entries = vec![(0, genesis("id"))];
        let governance = structural(&entries);
        let error = governance.log_id_for(1).expect_err("no log_id");
        assert!(error.to_string().contains("REQUIRED"), "{error}");
        assert!(error.to_string().contains("no check to perform"), "{error}");

        // The specification spelling resolves.
        let entries = vec![(0, genesis("log_id"))];
        let governance = structural(&entries);
        assert_eq!(governance.log_id_for(1).expect("log id"), family(0xaa));
    }
}
