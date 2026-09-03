//! Establishing an AHL-backed view of a log, in the order the design note fixes.
//!
//! `closure` and `reconstruct` are AHL-backed only when **all** of the following are
//! established, and the CLI refuses to produce a result otherwise:
//!
//! 1. a fixed checkpoint `C`, chosen explicitly, **authenticated**: a signed object whose
//!    signature resolves through the governing manifest version, selected by `tree_size`;
//! 2. full authenticated enumeration of `[0, tree_size(C))`, the range proof verified and
//!    `C`'s root **recomputed** from the enumerated leaves;
//! 3. the neighbouring consistency relationships of adaptor §6.6 — predecessor, and successor
//!    where one exists;
//! 4. only now is `C` classified **series-usable**, and only as `run-observed`;
//! 5. every envelope's signature resolving to a key active at its entry index, under the
//!    manifest version governing that index, plus the governance checks of core §2.1–§2.3;
//! 6. trigger effectiveness, where the command needs a trigger;
//! 7. all tree material the closure needs, verified rather than assumed.
//!
//! # Steps 1 and 2 are a joint fixed point, not a sequence
//!
//! Written as a sequence, step 1 precedes step 2. In practice it cannot: authenticating `C`
//! needs the log key from the manifest version governing `tree_size(C)`, that manifest is an
//! entry in the log, and trusting entries needs `C`'s root. The two are mutually dependent.
//!
//! This implementation therefore establishes them as a **joint fixed point** and says so:
//! candidate entries are fetched under the candidate `C`, the range proofs and the recomputed
//! root tie those entries to `C.root_hash`, the governance chain inside them is validated from
//! the **locally configured** genesis anchor, and only a chain that both opens `C`'s root and
//! anchors to configured policy can supply the key that then validates `C`'s signature. All
//! three hold simultaneously or the result is unverifiable. Nothing is trusted on the way
//! round: the entries are content-addressed against `C`'s root, and the anchor comes from
//! policy rather than from the log. This is recorded as an ambiguity in the frozen sources
//! rather than presented as a reading of them.
//!
//! # `run-observed`, and why nothing stronger is claimed
//!
//! The frozen sources define no authenticated completeness proof over *any* history a server
//! publishes. A mirror can withhold a successor and make an older `C` look newest; a witness
//! can serve an older valid cosigned checkpoint. So the CLI never claims unconditional series
//! usability or "the latest witnessed checkpoint" — it claims usability *as of what this run
//! observed*, and labels it that way.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use crate::cache;
use crate::checkpoint::{
    consistency_verifies, equivocation_floor, series_order_key, Checkpoint, SigningForm,
};
use crate::enumerate::{Enumerator, LeafForm};
use crate::error::{CliError, CliResult};
use crate::governance::Governance;
use crate::net::{FetchFailure, Fetcher, Request};
use crate::policy::{LoadedPolicy, NetworkLimits};
use crate::report::Finding;

/// How wide one subrange request is, unless a caller narrows it.
pub const DEFAULT_CHUNK: u64 = 512;

/// The **verified statement view**: dense by entry index, and the only view an
/// authenticated-mode decision may read.
///
/// Two normative rules are applied when this is built, in this order, and applying them here
/// rather than at each use site is the point — a second `&[Value]` with the same shape is how
/// one call site ends up reading the raw enumeration by accident.
///
/// 1. **An envelope whose signatures do not all verify is not an AHL statement** (core §2.1),
///    and adaptor §7.4.1 spells out the consequence for a log without submission controls:
///    anyone who can reach the endpoint can place a well-formed object at a real index with a
///    real inclusion proof, and a verifier must ignore it rather than treat the log as
///    compromised.
/// 2. **A duplicate statement id is void from the second occurrence on** (core §2.1: "if
///    duplicates occur, the one with the smallest entry index governs and later ones are
///    void").
///
/// The order matters. Excluding non-statements *first* means a hostile party cannot void a
/// genuine statement by anchoring the same payload with a broken signature at a smaller index
/// — which is exactly what "later ones are void" would otherwise hand them. Core §2.1 does not
/// say which of the two rules runs first; this is recorded as an ambiguity in the README, and
/// the reading implemented here is the only one that is not trivially exploitable.
///
/// A voided position is **occupied by a placeholder**, never removed: the entry index is AHL's
/// only ordering primitive, and closing a gap would shift every index after it.
#[derive(Debug, Clone, Default)]
pub struct Statements {
    inner: Vec<Value>,
}

/// What a voided position carries. Contributes no edges, no trigger, and no introduction.
fn voided() -> Value {
    json!({ "payload": { "type": "not-a-statement" } })
}

impl Statements {
    /// The statement at `index`, if the checkpoint commits it and it is a statement at all.
    #[must_use]
    pub fn get(&self, index: u64) -> Option<&Value> {
        self.inner.get(usize::try_from(index).ok()?)
    }

    /// `(entry_index, envelope)` for every position, voided ones included.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &Value)> {
        self.inner
            .iter()
            .enumerate()
            .map(|(index, envelope)| (u64::try_from(index).unwrap_or(u64::MAX), envelope))
    }

    /// The dense envelope slice `ahl-core`'s closure functions take, where the position in the
    /// slice *is* the entry index.
    #[must_use]
    pub fn envelopes(&self) -> &[Value] {
        &self.inner
    }

    /// How many positions the view covers.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the view is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// The payload of the statement at `index`, if there is one.
    #[must_use]
    pub fn payload(&self, index: u64) -> Option<&Value> {
        self.get(index)?.get("payload")
    }

    /// The statement type at `index`, if there is one.
    #[must_use]
    pub fn statement_type(&self, index: u64) -> Option<&str> {
        self.payload(index)?.get("type")?.as_str()
    }

    /// Build the view from an enumeration, applying both rules above.
    ///
    /// # Errors
    ///
    /// [`CliError::RuleFired`] when an anchored **statement** declares a type outside core
    /// §2.3's seven. Design note §6 fixes that row at outcome `1` in authenticated mode —
    /// "never skipped, never inert" — and the reason is the one that makes a verifier useful:
    /// an unknown type may carry edges, authority or scope this build cannot read, so treating
    /// it as contributing nothing is the CLI silently deciding it contributes nothing. Only
    /// entries that survive rule 1 are tested, because an object whose signatures do not verify
    /// is not a statement at all and adaptor §7.4.1 requires ignoring it rather than treating
    /// the log as compromised.
    fn build(entries: &[(u64, Value)], governance: &Governance) -> CliResult<(Self, Vec<Finding>)> {
        let mut inner = Vec::with_capacity(entries.len());
        let mut findings = Vec::new();
        let mut seen: BTreeMap<String, u64> = BTreeMap::new();

        for (index, envelope) in entries {
            // Rule 1.
            if !governance.envelope_verifies_at(envelope, *index).unwrap_or(false) {
                findings.push(Finding::new(
                    "entry-is-not-a-statement",
                    format!(
                        "the entry at entry index {index} carries a signature that does not \
                         resolve to a key active at that index, or does not verify; core spec \
                         §2.1 makes it not an AHL statement, so it is excluded from every \
                         decision and reported rather than being treated as evidence"
                    ),
                ));
                inner.push(voided());
                continue;
            }
            // An anchored statement of a type this build does not know is outcome 1, and it
            // is checked before the duplicate rule so that "never skipped" holds for a
            // repeated one too.
            let kind = envelope
                .get("payload")
                .and_then(|payload| payload.get("type"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !crate::corpus::STATEMENT_TYPES.contains(&kind) {
                return Err(CliError::RuleFired(format!(
                    "the statement at entry index {index} declares type `{kind}`, which is not \
                     one of the seven core spec §2.3 defines. It is anchored and its signatures \
                     verify, so it is an AHL statement whose meaning this build cannot read; \
                     leaving it inert would be a decision that it carries no edge, no authority \
                     and no scope, which nothing establishes"
                )));
            }

            // Rule 2, over the survivors of rule 1 only.
            match ahl_core::statement_id(envelope) {
                Ok(statement_id) => {
                    if let Some(governing) = seen.get(&statement_id) {
                        findings.push(Finding::new(
                            "statement-void-duplicate-id",
                            format!(
                                "the entry at entry index {index} repeats the statement id \
                                 first anchored at {governing}; core spec §2.1 makes the \
                                 smallest entry index govern and voids later ones, so this \
                                 position is excluded from every decision"
                            ),
                        ));
                        inner.push(voided());
                        continue;
                    }
                    seen.insert(statement_id, *index);
                    inner.push(envelope.clone());
                }
                Err(source) => {
                    findings.push(Finding::new(
                        "entry-is-not-a-statement",
                        format!("the entry at entry index {index} has no statement id: {source}"),
                    ));
                    inner.push(voided());
                }
            }
        }
        Ok((Self { inner }, findings))
    }
}

/// An established view: a series-usable checkpoint, its verified statements, and its
/// governance.
///
/// There is deliberately **no** raw-entry field. The enumeration is consumed while
/// establishing the view and is not carried forward, so no later decision can read it by
/// accident.
#[derive(Debug)]
pub struct Anchored {
    /// The selected checkpoint, authenticated and series-usable as of this run.
    pub checkpoint: Checkpoint,
    /// The verified statement view — the only view an authenticated decision reads.
    pub statements: Statements,
    /// The governance state resolved from the enumeration under adaptor §7.4.1.
    pub governance: Governance,
    /// Findings raised while establishing the view.
    pub findings: Vec<Finding>,
}

/// The client half of a mirror conversation.
#[derive(Debug)]
pub struct Mirror<'a, F: Fetcher> {
    fetcher: &'a F,
    base: String,
    signing_form: SigningForm,
    leaf_form: LeafForm,
    limits: NetworkLimits,
    chunk: u64,
}

impl<'a, F: Fetcher> Mirror<'a, F> {
    /// Bind a client to `base` under the pinned adaptor profile.
    ///
    /// # Errors
    ///
    /// [`CliError::ProfileLimitation`] if this build implements neither the checkpoint signing
    /// form nor the leaf construction of `profile_id`.
    pub fn new(
        fetcher: &'a F,
        base: &str,
        profile_id: &str,
        limits: NetworkLimits,
    ) -> CliResult<Self> {
        Ok(Self {
            fetcher,
            base: base.trim_end_matches('/').to_owned(),
            signing_form: SigningForm::for_profile(profile_id)?,
            leaf_form: LeafForm::for_profile(profile_id)?,
            limits,
            chunk: DEFAULT_CHUNK,
        })
    }

    /// Narrow the subrange width, for tests and for constrained deployments.
    #[must_use]
    pub const fn with_chunk(mut self, chunk: u64) -> Self {
        self.chunk = chunk;
        self
    }

    fn get(&self, path: &str) -> CliResult<Value> {
        // Never cached: see `series` and `checkpoint_at` for the two reasons.
        let response = self
            .fetcher
            .fetch(&Request::get(format!("{}{path}", self.base)))
            .map_err(FetchFailure::into_cli_error)?;
        if response.status != 200 {
            return Err(CliError::EvidenceMissing(format!(
                "the mirror answered {} for `{path}`; a status is an operational failure, never \
                 refusal evidence",
                response.status
            )));
        }
        serde_json::from_slice(&response.body).map_err(|source| {
            CliError::EvidenceMissing(format!("`{path}` did not answer with JSON: {source}"))
        })
    }

    /// The checkpoint series as this run observed it.
    ///
    /// Never served from cache: "what does the log publish now?" answered from a cache is
    /// "what did the log publish then", and a valid old answer is a replay.
    ///
    /// # Errors
    ///
    /// [`CliError::EvidenceMissing`] when the mirror does not answer usably.
    pub fn series(&self) -> CliResult<Vec<Checkpoint>> {
        let value = self.get("/v1/checkpoints")?;
        let members = value.as_array().ok_or_else(|| {
            CliError::EvidenceMissing("the checkpoint series is not an array".to_owned())
        })?;
        members.iter().map(Checkpoint::from_value).collect()
    }

    /// A consistency proof between two sizes, as this mirror serves it.
    ///
    /// Adaptor §8.3 fixes the serialization exactly: a JSON array of `sha256:<hex>` family
    /// strings, in the order the RFC 9162 algorithm produces, **and nothing else**. Every
    /// element is therefore required to be such a string. Dropping the elements that are not
    /// — which is what a `filter_map` here would do — and then certifying a neighbour
    /// relationship on what is left would verify a *different, shorter* proof than the one the
    /// mirror served, and an attacker choosing which elements to make non-strings would be
    /// choosing which proof gets checked. Any departure from the serialization makes the
    /// remote evidence unusable: outcome `3`, never a verified neighbour.
    ///
    /// # Errors
    ///
    /// [`CliError::EvidenceMissing`] when the mirror does not answer usably, or answers with
    /// anything but an array of `sha256:<hex>` family strings.
    pub fn consistency_path(&self, from: u64, to: u64) -> CliResult<Vec<String>> {
        let value = self.get(&format!("/v1/consistency?from={from}&to={to}"))?;
        let path = value.get("consistency_path").and_then(Value::as_array).ok_or_else(|| {
            CliError::EvidenceMissing(format!(
                "the mirror served no `consistency_path` array for {from}→{to}; adaptor §8.3 \
                 serializes a consistency proof as a JSON array of `sha256:<hex>` family \
                 strings"
            ))
        })?;
        path.iter()
            .enumerate()
            .map(|(at, element)| {
                let hash = element.as_str().ok_or_else(|| {
                    CliError::EvidenceMissing(format!(
                        "element {at} of the consistency proof for {from}→{to} is not a string; \
                         adaptor §8.3 admits `sha256:<hex>` family strings and nothing else, so \
                         this proof is unusable rather than partly readable"
                    ))
                })?;
                ahl_core::parse_hash_hex(hash).map_err(|source| {
                    CliError::EvidenceMissing(format!(
                        "element {at} of the consistency proof for {from}→{to} is not a \
                         `sha256:<hex>` family string: {source}"
                    ))
                })?;
                Ok(hash.to_owned())
            })
            .collect()
    }

    /// Retrieve one entry's bytes by AHL entry id, content-checked against the id requested
    /// (adaptor §10.1.1 verifier duty 1).
    ///
    /// # Errors
    ///
    /// [`CliError::EvidenceMissing`] when the bytes are absent or do not digest to the id.
    pub fn entry_by_id(
        &self,
        entry_id: &str,
        identity: &cache::CheckpointIdentity,
    ) -> CliResult<Value> {
        let request = Request::get(format!("{}/v1/entries/{entry_id}", self.base));
        let key = cache::request_key(identity, &request);
        let request = request.cached_under(key);

        // Content-addressed, and revalidating: a cached answer whose bytes do not digest to
        // the id requested is evicted and refetched once, then reported.
        crate::net::fetch_revalidating(self.fetcher, &request, |response: &crate::net::Response| {
            if response.status != 200 {
                // Absence is a fact about the interface, not about the corpus: it is never
                // read as evidence that no such entry was ever anchored.
                return Err(CliError::EvidenceMissing(format!(
                    "the mirror does not hold entry `{entry_id}` (status {}); absence is \
                     unavailability, never a negative result about the corpus",
                    response.status
                )));
            }
            if ahl_core::sha256_hex(&response.body) != entry_id {
                return Err(CliError::EvidenceMissing(format!(
                    "the bytes served for `{entry_id}` do not digest to it; retrieval is \
                     self-checking and a substitution is detected here"
                )));
            }
            serde_json::from_slice(&response.body).map_err(|source| {
                CliError::EvidenceMissing(format!("entry `{entry_id}` is not JSON: {source}"))
            })
        })
    }
}

/// Establish an AHL-backed view at `tree_size`.
///
/// # Errors
///
/// [`CliError::EquivocationAtOrBeyondFloor`] when the result would be grounded at or beyond a
/// confirmed divergence — positive proof of misbehaviour, not absence of evidence.
/// [`CliError::EvidenceMissing`] for every other failure to establish the view: a hostile or
/// merely broken server disproves nothing about the user's artifact.
pub fn establish<F: Fetcher>(
    mirror: &Mirror<'_, F>,
    policy: &LoadedPolicy,
    tree_size: u64,
) -> CliResult<Anchored> {
    let series = mirror.series()?;
    let selected = governing_member(&series, tree_size)?;
    establish_under(mirror, policy, &series, selected)
}

/// The published member at `tree_size` that governs, by the series order of core §7.3.
///
/// Ordering is `(tree_size, checkpoint_time)`, so the member with the earliest
/// `checkpoint_time` governs: a quiet log republishes at unchanged size, and §7.3 fixes which
/// of those members a selection lands on. Taking whichever member the mirror happened to
/// serialize first would let the server pick.
fn governing_member(series: &[Checkpoint], tree_size: u64) -> CliResult<Checkpoint> {
    series
        .iter()
        .filter(|member| member.tree_size == tree_size)
        .min_by_key(|member| series_order_key(member))
        .cloned()
        .ok_or_else(|| {
            CliError::EvidenceMissing(format!(
                "the mirror published no checkpoint at tree_size {tree_size}; checkpoint \
                 selection is explicit and is never inferred"
            ))
        })
}

/// Establish the view under one candidate checkpoint.
fn establish_under<F: Fetcher>(
    mirror: &Mirror<'_, F>,
    policy: &LoadedPolicy,
    series: &[Checkpoint],
    selected: Checkpoint,
) -> CliResult<Anchored> {
    let tree_size = selected.tree_size;
    let mut findings = Vec::new();

    // --- steps 1 and 2, as a joint fixed point ---------------------------------------
    let enumerator = Enumerator::new(
        mirror.fetcher,
        &mirror.base,
        mirror.leaf_form,
        mirror.limits,
        mirror.chunk,
    );
    let entries = enumerator.enumerate_and_recompute(&selected)?;

    // Governance is resolved incrementally under adaptor §7.4.1 — every later statement
    // verified under the key set the chain established before it — and anchored to the
    // **locally configured** genesis. A forged manifest in the enumeration is ignored for key
    // resolution and reported; it cannot contribute the log key that authenticates `C`.
    let (governance, governance_findings) =
        Governance::resolve(&entries, &policy.trust).map_err(remote_candidate)?;
    findings.extend(governance_findings);
    findings.extend(governance.log_object_findings());

    let declared_log_id = governance.log_id_for(tree_size).map_err(remote_candidate)?;
    if declared_log_id != selected.log_id {
        return Err(CliError::EvidenceMissing(format!(
            "the checkpoint names log `{}` but the manifest version governing tree_size \
             {tree_size} declares `{declared_log_id}`",
            selected.log_id
        )));
    }
    let log_keys = governance.log_keys_for(tree_size).map_err(remote_candidate)?;
    if !selected.signature_verifies(mirror.signing_form, &log_keys)? {
        return Err(CliError::EvidenceMissing(
            "the selected checkpoint's log signature does not verify under the key set the \
             governing manifest version declares"
                .to_owned(),
        ));
    }

    // --- divergence: authentication is enough to condemn ------------------------------
    // Every member that authenticates counts, series-usable or not: divergence is visible from
    // checkpoint metadata alone, and requiring usability first would let a deployment defer
    // detection indefinitely by never recomputing the branch it dislikes (adaptor §6.6.1).
    let mut authenticated = Vec::new();
    for member in series {
        let Ok(keys) = governance.log_keys_for(member.tree_size) else { continue };
        if member.signature_verifies(mirror.signing_form, &keys).unwrap_or(false) {
            authenticated.push(member.clone());
        }
    }
    if let Some(floor) = equivocation_floor(&authenticated) {
        if tree_size >= floor {
            // Positive proof of misbehaviour, and a branch is never chosen.
            return Err(CliError::EquivocationAtOrBeyondFloor { floor });
        }
        findings.push(Finding::new(
            "divergence-below-floor",
            format!(
                "the checkpoint series equivocates from tree_size {floor}; this result is \
                 grounded strictly below that floor and members below a divergence remain \
                 usable, so the divergence is carried rather than adjudicated"
            ),
        ));
    }

    // --- an unresolved divergence is a floor too, and this result may not sit at or beyond it
    //
    // The floor rule above condemns a divergence both of whose members authenticate under the
    // chain this corpus authorizes. What is left are sizes where the mirror published more
    // than one root and only one of them resolves here. That is *not* the same as having
    // established that the others are bogus: a checkpoint is authenticated under the manifest
    // version governing its own `tree_size` in its own corpus (adaptor §6.5 step 4, §6.6), and
    // this run holds one enumeration interface, whose request names a range and a tree size
    // and never a root (§10.3) — so it has no way to ask *this* mirror for the entries behind
    // a second root at one size. Another party might well obtain them: §10.3 leaves transport
    // unconstrained and admits a published static archive or an independent mirror, and §6.6
    // takes entry material from any source. The limit is on what this run established, not on
    // what is obtainable.
    //
    // Adaptor §5.2.2 ends the canonical series **from the lowest size at which divergence
    // occurs**, and nothing may be grounded at or beyond that point. An unresolved divergence
    // is a candidate for that floor, so the same boundary applies to it: at or below the size
    // this result is grounded on it is fatal, and the honest outcome is `3` — material that
    // could not be established, never an accusation, which §7 reserves for two members that
    // both authenticate. Strictly *above* it the result is grounded below a floor even in the
    // worst reading, members below a divergence remain usable, and one bogus object from a
    // mirror must not derail an honest run — so it is carried as a finding.
    let unresolved = unresolved_divergences(series, &authenticated);
    if let Some(floor) = unresolved.iter().copied().find(|size| *size <= tree_size) {
        return Err(CliError::EvidenceMissing(format!(
            "the mirror published more than one root at tree_size {floor} and only one of them \
             resolves under the manifest chain this corpus authorizes. Whether another is \
             authentic under a chain of its own was not established in this run: the \
             enumeration interface of adaptor §10.3 names a range and a tree size, never a \
             root, so this client has no request that separates two roots at one size from \
             this mirror. A divergence at {floor} would end the canonical series from there \
             (§5.2.2), and this result would be grounded at tree_size {tree_size}, at or \
             beyond it. Nothing may be grounded at or beyond a divergence that has not been \
             ruled out"
        )));
    }
    findings.extend(unresolved.iter().map(|size| {
        Finding::new(
            "mirror-served-differing-roots",
            format!(
                "the mirror published more than one root at tree_size {size}, of which one \
                 authenticates for the bound log; objects that do not authenticate are \
                 untrusted material from a server and carry no accusation about the log. This \
                 result is grounded at tree_size {tree_size}, strictly below that size, and \
                 members below a divergence remain usable"
            ),
        )
    }));

    // --- step 3: neighbouring consistency --------------------------------------------
    findings.extend(check_neighbours(mirror, &authenticated, &selected)?);

    // --- step 5: the verified statement view, and nothing else carried forward ---------
    let (statements, statement_findings) = Statements::build(&entries, &governance)?;
    findings.extend(statement_findings);

    findings.sort();
    findings.dedup();
    Ok(Anchored { checkpoint: selected, statements, governance, findings })
}

/// A failure while reading remote material is missing evidence, never a disproved artifact.
fn remote_candidate(error: CliError) -> CliError {
    match error.outcome() {
        crate::outcome::Outcome::Invalid => CliError::EvidenceMissing(format!(
            "the material the mirror served is unusable: {error}"
        )),
        _ => error,
    }
}

/// The tree sizes at which the mirror published more than one root **without** this run
/// establishing that more than one of them authenticates, ascending.
///
/// These are the divergences the run could neither confirm nor rule out. A size where two or
/// more members authenticate is *not* here: that one is confirmed and the floor rule of
/// [`equivocation_floor`] adjudicates it, because design note §7 reserves an accusation for two
/// members that both authenticate — without the qualifier a hostile mirror publishing one bogus
/// object could make the CLI accuse an honest log.
///
/// Ascending order is load-bearing: adaptor §5.2.2 ends the series from the **lowest** size at
/// which divergence occurs, so the caller takes the first entry at or below the size it would
/// ground on and refuses there.
fn unresolved_divergences(published: &[Checkpoint], authenticated: &[Checkpoint]) -> BTreeSet<u64> {
    let mut roots: BTreeMap<u64, BTreeSet<&str>> = BTreeMap::new();
    for member in published {
        roots.entry(member.tree_size).or_default().insert(&member.root_hash);
    }
    roots
        .into_iter()
        .filter(|(_, published_roots)| published_roots.len() > 1)
        .filter(|(tree_size, _)| {
            authenticated
                .iter()
                .filter(|member| member.tree_size == *tree_size)
                .map(|member| member.root_hash.as_str())
                .collect::<BTreeSet<&str>>()
                .len()
                <= 1
        })
        .map(|(tree_size, _)| tree_size)
        .collect()
}

/// Verify the §6.6 neighbour relationships in **series order**: predecessor, and successor
/// where one exists.
///
/// Neighbours are taken in the `(tree_size, checkpoint_time)` order of core §7.3, not by
/// `tree_size` alone. A quiet log republishes at unchanged size, so a member sharing
/// `selected`'s `tree_size` is a genuine series neighbour and skipping it would leave a
/// relationship §6.6 requires unverified.
///
/// # The predecessor is required, and the one exemption is not observable
///
/// Design note §3 item 3 requires the predecessor relationship **always**. Adaptor §5.2.2 item
/// 3 does describe a member that has none — the earliest one a deployment published, since an
/// operator may first publish at a size larger than the genesis checkpoint — but that is a
/// fact about the *deployment*, and no client can establish it.
///
/// "The mirror served nothing earlier" is not "the deployment published nothing earlier". A
/// mirror answering `/v1/checkpoints` is a server label, and design note §2 rule 3 makes server
/// labels not evidence; §10 records that the frozen sources define no authenticated
/// completeness proof over *any* history a server publishes, which is the same missing
/// primitive that stops "where a successor exists" from being decidable. Reading a short series
/// response as the exemption would hand every mirror a switch that turns a missing relationship
/// into a complete answer: withhold the predecessor, and the run that should have reported
/// missing evidence reports `valid` instead.
///
/// So the exemption is never claimed. Where no authenticated predecessor is established the
/// outcome is `3` with the missing element named — the same answer the CLI gives for any other
/// evidence it was not handed. The asymmetry with the successor clause is the design note's
/// own: predecessor *always*, successor *where one exists*.
fn check_neighbours<F: Fetcher>(
    mirror: &Mirror<'_, F>,
    authenticated: &[Checkpoint],
    selected: &Checkpoint,
) -> CliResult<Vec<Finding>> {
    let mut findings = Vec::new();
    let position = series_order_key(selected);

    let predecessor = authenticated
        .iter()
        .filter(|member| series_order_key(member) < position)
        .max_by_key(|member| series_order_key(member));
    let successor = authenticated
        .iter()
        .filter(|member| series_order_key(member) > position)
        .min_by_key(|member| series_order_key(member));

    let Some(previous) = predecessor else {
        return Err(CliError::EvidenceMissing(format!(
            "no authenticated series member precedes tree_size {} in this run, so the \
             predecessor relationship adaptor §6.6 requires could not be verified. Design note \
             §3 requires that relationship always. Adaptor §5.2.2 item 3 does allow a \
             deployment to have published no earlier member, but that is a fact about the \
             deployment and no client can establish it: a short answer from \
             `/v1/checkpoints` is a server label, and server labels are not evidence, so a \
             withheld predecessor is indistinguishable from an absent one. The relationship is \
             reported as not established rather than assumed away",
            selected.tree_size
        )));
    };
    verify_neighbour(mirror, previous, selected)?;

    match successor {
        Some(next) => verify_neighbour(mirror, selected, next)?,
        // "Where one exists" is not decidable against an untrusted mirror: no authenticated
        // completeness proof over checkpoint-series history is defined, so a mirror can
        // withhold a successor and make an older C look newest.
        None => findings.push(Finding::new(
            "series-successor-not-observed",
            format!(
                "this run observed no series member after tree_size {}; that a successor does \
                 not exist is not establishable against an untrusted mirror, so series \
                 usability is claimed only as of what this run observed",
                selected.tree_size
            ),
        )),
    }
    Ok(findings)
}

/// Verify one neighbour relationship, `earlier` → `later` in series order.
fn verify_neighbour<F: Fetcher>(
    mirror: &Mirror<'_, F>,
    earlier: &Checkpoint,
    later: &Checkpoint,
) -> CliResult<()> {
    if earlier.tree_size == later.tree_size {
        // Two members at one size restate one tree (adaptor §5.2.2 item 2), so their
        // relationship is settled by their roots and there is no proof to fetch: RFC 9162
        // defines no consistency proof between a size and itself, and inventing a request the
        // profile does not define would be worse than checking what the objects already say.
        // Equal roots is the append-only extension of length zero; unequal roots is divergence,
        // which the floor rule has already adjudicated before this runs — so reaching here with
        // unequal roots means one of the two did not authenticate, and the pair is unusable
        // rather than an accusation.
        if earlier.root_hash == later.root_hash {
            return Ok(());
        }
        return Err(CliError::EvidenceMissing(format!(
            "two members at tree_size {} carry different roots and only one of them \
             authenticates, so the neighbour relationship adaptor §6.6 requires cannot be \
             verified; an object that does not authenticate is untrusted material from a \
             server, never a finding about the log",
            earlier.tree_size
        )));
    }

    let path = mirror.consistency_path(earlier.tree_size, later.tree_size)?;
    if consistency_verifies(earlier, later, &path)? {
        return Ok(());
    }
    Err(CliError::EvidenceMissing(format!(
        "consistency from the series member at tree_size {} to the one at {} does not verify",
        earlier.tree_size, later.tree_size
    )))
}

/// Which trigger governs a record at `C`, established over the whole enumerated range.
///
/// Not merely that *a* trigger is anchored, in scope and signed by an authorized key, but that
/// **this** trigger governs: all competing triggers are enumerated over the required range,
/// **every** candidate envelope signature is verified *before* authority is compared — an
/// invalid signature never governs — and the governing trigger is the one with the greatest
/// entry index. Without this, a hostile corpus makes the CLI compute a closure from an older
/// trigger a later one supersedes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoverningTrigger {
    /// Entry index of the trigger that governs.
    pub entry_index: u64,
    /// Its statement id.
    pub statement_id: String,
    /// The record it names.
    pub record: (String, String),
    /// Competing triggers that were enumerated and rejected, with the reason.
    pub findings: Vec<Finding>,
}

/// Establish the governing trigger for `record` at the anchored view.
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] when no effective trigger exists for the record, or when the
/// record was never introduced at all.
pub fn governing_trigger(
    anchored: &Anchored,
    dataset: &str,
    record: &str,
) -> CliResult<GoverningTrigger> {
    let introduction =
        introduction_index(&anchored.statements, dataset, record).ok_or_else(|| {
            CliError::EvidenceMissing(format!(
                "no anchored `ingestion` or `derivation` introduces `{dataset}`/`{record}` in \
             [0, {}); authority cannot predate the introduction that creates it",
                anchored.checkpoint.tree_size
            ))
        })?;

    let mut findings = Vec::new();
    let mut governing: Option<(u64, String)> = None;

    for (index, envelope) in anchored.statements.iter() {
        let Some(payload) = envelope.get("payload") else { continue };
        let kind = payload.get("type").and_then(Value::as_str).unwrap_or_default();
        if !matches!(kind, "retraction" | "correction") {
            continue;
        }
        if payload.get("dataset").and_then(Value::as_str) != Some(dataset)
            || payload.get("record").and_then(Value::as_str) != Some(record)
        {
            continue;
        }

        // A trigger anchored before the record's introduction is never effective.
        if index < introduction {
            findings.push(Finding::new(
                "trigger-predates-introduction",
                format!(
                    "the trigger at entry index {index} precedes the record's introduction at \
                     {introduction} and is never effective"
                ),
            ));
            continue;
        }

        // Signature verification and duplicate voiding already happened when the view was
        // built, so anything reached here is a statement: an invalid signature never governs
        // because it is not in this view at all.
        let signers = signer_key_ids(envelope);
        let authority = authority_for(anchored, dataset, introduction, index);
        if signers.is_disjoint(&authority) {
            // Triggers from other keys anchor as challenges: surfaced, never traversed.
            findings.push(Finding::new(
                "trigger-anchored-as-challenge",
                format!(
                    "the trigger at entry index {index} is not signed by the record's \
                     authority and anchors as a challenge; challenges are never traversed"
                ),
            ));
            continue;
        }

        let statement_id = ahl_core::statement_id(envelope).map_err(|source| {
            CliError::EvidenceMissing(format!("entry {index} has no statement id: {source}"))
        })?;
        // Among effective triggers for one record, the greatest entry index governs.
        if governing.as_ref().is_none_or(|(at, _)| index > *at) {
            governing = Some((index, statement_id));
        }
    }

    let (entry_index, statement_id) = governing.ok_or_else(|| {
        CliError::EvidenceMissing(format!(
            "no effective trigger for `{dataset}`/`{record}` is anchored in [0, {})",
            anchored.checkpoint.tree_size
        ))
    })?;
    findings.sort();
    findings.dedup();
    Ok(GoverningTrigger {
        entry_index,
        statement_id,
        record: (dataset.to_owned(), record.to_owned()),
        findings,
    })
}

/// The entry index at which `(dataset, record)` is introduced, if it is.
///
/// Reads the **verified** view: a forged, non-verifying ingestion or derivation must not be
/// able to establish an earlier introduction, which would move the authority consulted for a
/// later, genuine trigger.
#[must_use]
pub fn introduction_index(statements: &Statements, dataset: &str, record: &str) -> Option<u64> {
    statements.iter().find_map(|(index, envelope)| {
        let payload = envelope.get("payload")?;
        match payload.get("type")?.as_str()? {
            "ingestion" => (payload.get("dataset")?.as_str()? == dataset
                && payload.get("record")?.as_str()? == record)
                .then_some(index),
            "derivation" => payload
                .get("outputs")?
                .as_array()?
                .iter()
                .any(|output| {
                    output.get("dataset").and_then(Value::as_str) == Some(dataset)
                        && output.get("record").and_then(Value::as_str) == Some(record)
                })
                .then_some(index),
            _ => None,
        }
    })
}

/// The key set entitled to trigger `(dataset, record)`.
///
/// For an **ingested** record it is the dataset authority the manifest declares. For a
/// **derived** record it is the introducing producer's key set **as of the trigger's entry
/// index** — not the introduction index, so a key rotation between the two applies. The
/// introduction is read from the verified view for the same reason as above.
fn authority_for(
    anchored: &Anchored,
    dataset: &str,
    introduction: u64,
    trigger_index: u64,
) -> BTreeSet<String> {
    let introduced_by_ingestion =
        anchored.statements.statement_type(introduction) == Some("ingestion");

    if introduced_by_ingestion {
        anchored.governance.dataset_authority(trigger_index, dataset).unwrap_or_default()
    } else {
        anchored.governance.producer_keys_at(trigger_index).keys().cloned().collect()
    }
}

fn signer_key_ids(envelope: &Value) -> BTreeSet<String> {
    envelope
        .get("signatures")
        .and_then(Value::as_array)
        .map(|signatures| {
            signatures
                .iter()
                .filter_map(|signature| signature.get("key_id")?.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Every committed tree root the **verified** statements reference, so missing material can be
/// named rather than discovered mid-traversal.
#[must_use]
pub fn required_tree_roots(statements: &Statements) -> BTreeMap<String, u64> {
    let mut roots = BTreeMap::new();
    for (_, envelope) in statements.iter() {
        let Some(payload) = envelope.get("payload") else { continue };
        if let (Some(root), Some(count)) = (
            payload.get("outputs_root").and_then(Value::as_str),
            payload.get("outputs_count").and_then(Value::as_u64),
        ) {
            roots.insert(root.to_owned(), count);
        }
        if let (Some(root), Some(count)) = (
            payload.get("affected_root").and_then(Value::as_str),
            payload.get("affected_count").and_then(Value::as_u64),
        ) {
            roots.insert(root.to_owned(), count);
        }
    }
    roots
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MirrorFixture;

    /// A manifest `log` object carrying every member core spec §7.3 makes REQUIRED, which
    /// `Governance::resolve` now checks before a manifest may govern.
    fn conformant_log_object() -> Value {
        json!({
            "log_id": format!("sha256:{}", hex::encode([0xaa_u8; 32])),
            "operator": "op",
            "adaptor": {
                "id": "ahl-test-log-v1",
                "hash": format!("sha256:{}", hex::encode([0xbb_u8; 32])),
            },
            "checkpoint_cadence": "PT1H",
            "cadence_epoch": "2026-01-01T00:00:00Z",
            "witness_grace_period": "PT15M",
            "keys": [],
        })
    }

    #[test]
    fn a_view_is_established_only_when_every_step_holds() {
        let fixture = MirrorFixture::conformance();
        let anchored = fixture.establish(8).expect("established");
        assert_eq!(anchored.checkpoint.tree_size, 8);
        assert_eq!(anchored.statements.len(), 8);
        assert_eq!(anchored.governance.manifest_indexes(), vec![0]);
    }

    #[test]
    fn a_checkpoint_the_mirror_never_published_is_never_inferred() {
        let fixture = MirrorFixture::conformance();
        let error = fixture.establish(7).expect_err("unpublished size");
        assert!(error.to_string().contains("never inferred"), "{error}");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
    }

    #[test]
    fn a_genesis_anchor_that_is_not_the_configured_one_is_missing_evidence_not_a_verdict() {
        let mut fixture = MirrorFixture::conformance();
        fixture.policy.trust.genesis_entry_id = format!("sha256:{}", "99".repeat(32));
        let error = fixture.establish(8).expect_err("wrong anchor");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
    }

    #[test]
    fn the_predecessor_relationship_is_verified_and_an_unverified_one_is_never_a_success() {
        // tree_size 13 has both a predecessor and a successor, so neither gap is reported.
        let fixture = MirrorFixture::conformance();
        let anchored = fixture.establish(13).expect("established");
        assert!(!anchored
            .findings
            .iter()
            .any(|finding| finding.code == "series-successor-not-observed"));

        // A member whose only published predecessor does not authenticate is missing evidence,
        // not a complete answer with a note attached.
        let fixture = MirrorFixture::conformance().with_series_from(8).with_foreign_log_key(8);
        assert!(fixture.establish(13).is_err(), "the predecessor did not authenticate");
        let error = fixture.establish(13).expect_err("the predecessor did not authenticate");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
        assert!(error.to_string().contains("predecessor relationship"), "{error}");
    }

    #[test]
    fn a_withheld_predecessor_never_buys_the_earliest_published_member_exemption() {
        // The deployment published members below tree_size 13; this mirror serves only 13 and
        // upward. Nothing in the response says so, and nothing can: adaptor §10.3 defines no
        // authenticated completeness proof over published history, so "the mirror served
        // nothing earlier" is a server label — design note §2 rule 3 — and not a fact about
        // what the deployment published. Reading it as adaptor §5.2.2 item 3's exemption
        // would hand every mirror a switch that turns a missing relationship into a complete
        // answer, so the exemption is never claimed.
        let withheld = MirrorFixture::conformance().with_series_from(13);
        let error = withheld.establish(13).expect_err("the predecessor was withheld");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable, "{error}");
        assert!(error.to_string().contains("no authenticated series member precedes"), "{error}");
        assert!(error.to_string().contains("server label"), "{error}");

        // The very same checkpoint, from a mirror that serves the history the deployment
        // published, establishes: the predecessor relationship is verifiable there.
        let full = MirrorFixture::conformance();
        assert_eq!(full.establish(13).expect("established").checkpoint.tree_size, 13);
    }

    #[test]
    fn the_genuinely_first_published_member_is_refused_and_the_refusal_is_deliberate() {
        // The case adaptor §5.2.2 item 3 describes and the frozen sources leave unreconciled:
        // an operator may first publish at a size larger than the genesis checkpoint, so that
        // member has no predecessor to relate to, while §6.6 requires the relationship for
        // series-usability. The fixture's smallest member is exactly that — nothing was
        // withheld and nothing failed to authenticate; there is genuinely nothing earlier.
        //
        // This crate does **not** implement the carve-out. Not because the carve-out is wrong,
        // but because a verifier cannot tell this case apart from a mirror that withheld the
        // predecessor: the sources fix no way to prove an observed member is really the first
        // one published. So the answer is `3` in both, and the reporting rule of design note
        // §10 is followed — the gap is named rather than decided in the client's favour.
        //
        // Pinned as a deliberate refusal so that it cannot become an accident of which sizes
        // the fixture happens to publish, and so that adopting the carve-out later is a visible
        // change to this test rather than a silent change of verdict.
        let fixture = MirrorFixture::conformance();
        let smallest = crate::testing::CHECKPOINT_SIZES
            .into_iter()
            .min()
            .expect("the fixture publishes a series");
        assert!(
            fixture.series().iter().all(|member| member.tree_size >= smallest),
            "nothing was withheld: this really is the first member published"
        );

        let error = fixture.establish(smallest).expect_err("no predecessor exists at all");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable, "{error}");
        assert!(error.to_string().contains("no authenticated series member precedes"), "{error}");
        assert!(
            error.to_string().contains("no client can establish it"),
            "the refusal must name why the carve-out is not claimed: {error}"
        );
    }

    #[test]
    fn a_second_root_at_the_grounded_size_is_never_answered_from_one_branch() {
        // The second member is signed by a key this corpus's manifest chain does not declare,
        // which is how a second branch looks from inside the first one: its own chain would
        // authorize its own log key, and this run holds one enumeration interface whose
        // request names a range and a tree size, never a root (§10.3) — so it has no way to
        // ask this mirror for the entries behind the other root.
        //
        // Answering from the branch that happens to resolve would report a complete closure
        // over a size the client cannot show carries one tree. It is `3` — material that could
        // not be established — and never `1`, which §7 reserves for two members that both
        // authenticate.
        let fixture = MirrorFixture::conformance().with_foreign_divergence_at(13);
        let error = fixture.establish(13).expect_err("two roots at the grounded size");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable, "{error}");
        assert!(error.to_string().contains("would be grounded at tree_size 13"), "{error}");
        assert!(!error.to_string().contains("equivocat"), "not an accusation: {error}");

        // Where both members at the grounded size authenticate, it is `1` and the floor is
        // named: that is positive proof, not absence of evidence.
        let equivocating = MirrorFixture::conformance().with_equivocation_at(13);
        let error = equivocating.establish(13).expect_err("both authenticate");
        assert!(matches!(error, CliError::EquivocationAtOrBeyondFloor { floor: 13 }), "{error}");
    }

    #[test]
    fn an_unresolved_divergence_below_the_grounded_size_is_a_floor_the_result_may_not_sit_beyond() {
        // Adaptor §5.2.2 ends the canonical series from the **lowest** size at which divergence
        // occurs, and nothing may be grounded at or beyond that point. A divergence the run
        // could not rule out is a candidate for that floor, so a result grounded *above* it is
        // grounded at or beyond a floor in the reading that has not been excluded — and the
        // outcome cannot be `0` just because the size the divergence sits at is not the one
        // the checkpoint was selected at.
        let fixture = MirrorFixture::conformance().with_foreign_divergence_at(8);
        let error = fixture.establish(20).expect_err("grounded beyond an unresolved floor");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable, "{error}");
        assert!(error.to_string().contains("at tree_size 8"), "{error}");
        assert!(error.to_string().contains("would be grounded at tree_size 20"), "{error}");
        assert!(!error.to_string().contains("equivocat"), "not an accusation: {error}");

        // The same shape with both members authenticating is the confirmed floor, and a result
        // grounded beyond it is positive proof: `1`, not `3`.
        let equivocating = MirrorFixture::conformance().with_equivocation_at(8);
        let error = equivocating.establish(20).expect_err("confirmed floor at 8");
        assert!(matches!(error, CliError::EquivocationAtOrBeyondFloor { floor: 8 }), "{error}");

        // Strictly *above* the grounded size the result sits below the floor under every
        // reading, members below a divergence remain usable, and one bogus object from a mirror
        // must not derail an honest run — so it is carried as a finding.
        let fixture = MirrorFixture::conformance().with_foreign_divergence_at(20);
        let anchored = fixture.establish(8).expect("grounded strictly below the divergence");
        assert!(anchored
            .findings
            .iter()
            .any(|finding| finding.code == "mirror-served-differing-roots"));
    }

    #[test]
    fn a_log_key_declared_but_not_yet_active_never_authenticates_a_checkpoint() {
        // Design note §2 rule 4: the signing key must be in the governing version's `log.keys`
        // **and active by `valid_from_index`**. Declaring a key is not adopting it, and a
        // checkpoint signed before its activation index is signed by a key the corpus had not
        // yet put in force.
        let fixture = MirrorFixture::conformance().with_future_activated_log_key();
        let size = fixture.appended_tree_size();
        let error = fixture.establish(size).expect_err("the key is not active yet");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable, "{error}");
        assert!(error.to_string().contains("does not verify"), "{error}");

        // The manifest version itself is sound, so checkpoints it does not govern are
        // unaffected.
        assert!(fixture.establish(20).is_ok());
    }

    #[test]
    fn a_forged_binding_in_a_key_transition_never_authorizes_a_successor_manifest() {
        // The recomputation of core §2.3.6 and adaptor §7.2 is about a `key_id -> pubkey`
        // **pair**, not about a place. A producer key genuinely in force signs a `key` add
        // carrying `{key_id: SHA-256(K_fake), pubkey: attacker_pubkey}`; the attacker then
        // signs a successor manifest naming that borrowed id, and a verifier that took the
        // binding on trust resolves the name to the attacker's key, verifies the signature and
        // lets the manifest join the chain. The log key it names then authenticates the
        // checkpoint over it, and a closure grounded there returns `0`.
        //
        // Every test of adaptor §7.4.1 passes on the way — the transition is signed by an
        // authorized key, the manifest links correctly to the version active before it, and
        // its own signature verifies against the key set the chain established. The rule that
        // stops it is the one about the pair, applied where the pair is read.
        let fixture = MirrorFixture::conformance().with_forged_key_transition();
        let size = fixture.appended_tree_size();
        let error = fixture.establish(size).expect_err("the binding does not recompute");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable, "{error}");
        assert!(error.to_string().contains("does not verify"), "{error}");

        // Checkpoints below the transition are unaffected: the refusal is of one statement,
        // not of the corpus (adaptor §7.4.1).
        assert!(fixture.establish(20).is_ok());
    }

    #[test]
    fn a_log_key_object_whose_id_does_not_recompute_never_resolves_a_checkpoint() {
        // Adaptor §7.2: "A verifier MUST recompute a key id from the public key it is given
        // and MUST reject a mismatch"; §6.5 step 4 repeats it at the point of use. Without
        // that, a manifest filing one party's public key under another party's id makes every
        // later lookup resolve the name a checkpoint carries to the key the manifest chose.
        let fixture = MirrorFixture::conformance().with_mismatched_log_key_id();
        let size = fixture.appended_tree_size();
        let error = fixture.establish(size).expect_err("the key id does not recompute");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable, "{error}");
        assert!(fixture.establish(20).is_ok(), "earlier versions are unaffected");
    }

    #[test]
    fn a_manifest_version_that_moves_the_cadence_epoch_never_governs() {
        // Core §7.3 and adaptor §7.3.2: the epoch is declared once, by the genesis manifest,
        // and repeated unchanged by every later version. A movable epoch would let an operator
        // re-anchor the series after the fact and erase an interval it failed to cover.
        let fixture = MirrorFixture::conformance().with_moved_cadence_epoch();
        let size = fixture.appended_tree_size();
        let error = fixture.establish(size).expect_err("the epoch moved");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable, "{error}");
        assert!(fixture.establish(20).is_ok(), "earlier versions are unaffected");
    }

    #[test]
    fn the_member_a_selection_lands_on_is_the_earliest_in_series_order_not_the_first_served() {
        // Core §7.3 orders a series by `(tree_size, checkpoint_time)` and makes the earliest
        // `checkpoint_time` govern where a selection lands on a size carrying several members.
        // Taking whichever member the mirror serialized first lets the server choose the
        // branch — and here the server's choice is the one whose root nothing recomputes,
        // which would answer a divergence with "evidence not obtained" instead of the verdict
        // the divergence actually supports.
        let fixture = MirrorFixture::conformance().with_equivocation_first_at(13);
        let error = fixture.establish(13).expect_err("at the floor");
        assert!(matches!(error, CliError::EquivocationAtOrBeyondFloor { floor: 13 }), "{error}");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Invalid);
    }

    #[test]
    fn a_republished_member_at_one_size_is_a_series_neighbour_not_a_member_to_skip() {
        // A quiet log MUST keep publishing at unchanged `tree_size` (core §7.3, adaptor §16
        // obligation 4), so a republished member is a genuine later member of the series under
        // the `(tree_size, checkpoint_time)` order — and §6.6 requires the relationship to a
        // following member where one exists. Neighbours taken by `tree_size` alone would step
        // straight past it and report a successor that was published as not observed.
        let newest = MirrorFixture::conformance().newest_tree_size();
        let fixture = MirrorFixture::conformance().with_republish_at(newest);
        let anchored = fixture.establish(newest).expect("established");

        // The mirror serialized the later republication first. Core §7.3 makes the earliest
        // `checkpoint_time` govern, so that is the member the result is reported against —
        // otherwise the server chooses which of its own publications a verdict names.
        assert_eq!(
            anchored.checkpoint.checkpoint_time,
            crate::testing::FIXED_TIME,
            "the earliest member at this size governs, not the first one served"
        );
        assert!(
            !anchored
                .findings
                .iter()
                .any(|finding| finding.code == "series-successor-not-observed"),
            "the republished member at this size is the successor: {:?}",
            anchored.findings
        );

        // Without the republication the same checkpoint is the newest observed member.
        let anchored = MirrorFixture::conformance().establish(newest).expect("established");
        assert!(anchored
            .findings
            .iter()
            .any(|finding| finding.code == "series-successor-not-observed"));
    }

    #[test]
    fn an_anchored_statement_of_an_unknown_type_is_a_verdict_not_an_inert_entry() {
        // §6: "Unknown claim type or unknown statement type, authenticated mode | 1 — never
        // skipped, never inert." The entry is anchored, committed by the checkpoint, and its
        // signature verifies under the key set in force at its index, so it is an AHL
        // statement; what a verifier cannot do is read what it means. Leaving it inert is the
        // CLI deciding it carries no edge, no authority and no scope — which nothing
        // establishes.
        let fixture = MirrorFixture::conformance().with_unknown_statement_type();
        let error =
            fixture.establish(fixture.appended_tree_size()).expect_err("unknown statement type");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Invalid, "{error}");
        assert!(error.to_string().contains("`attestation`"), "{error}");
        assert!(error.to_string().contains("one of the seven"), "{error}");

        // A checkpoint below it is unaffected: the statement is not committed there.
        assert!(fixture.establish(8).is_ok());
    }

    #[test]
    fn the_newest_observed_member_is_labelled_run_observed_rather_than_latest() {
        let fixture = MirrorFixture::conformance();
        let newest = fixture.newest_tree_size();
        let anchored = fixture.establish(newest).expect("established");
        assert!(anchored
            .findings
            .iter()
            .any(|finding| finding.code == "series-successor-not-observed"));
    }

    #[test]
    fn a_result_grounded_at_or_beyond_an_equivocation_floor_is_positive_proof_of_misbehaviour() {
        let fixture = MirrorFixture::conformance().with_equivocation_at(13);
        let error = fixture.establish(13).expect_err("at the floor");
        assert!(matches!(error, CliError::EquivocationAtOrBeyondFloor { floor: 13 }), "{error}");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Invalid);
    }

    #[test]
    fn a_result_grounded_below_the_floor_keeps_its_outcome_and_carries_the_divergence() {
        let fixture = MirrorFixture::conformance().with_equivocation_at(13);
        let anchored = fixture.establish(8).expect("below the floor");
        assert!(anchored.findings.iter().any(|finding| finding.code == "divergence-below-floor"));
    }

    #[test]
    fn a_checkpoint_signed_by_a_key_the_manifest_does_not_declare_does_not_authenticate() {
        let fixture = MirrorFixture::conformance().with_foreign_log_key(8);
        let error = fixture.establish(8).expect_err("foreign key");
        assert!(error.to_string().contains("does not verify"), "{error}");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
    }

    #[test]
    fn a_tampered_entry_breaks_the_root_recomputation() {
        let fixture = MirrorFixture::conformance().with_tampered_entry(3);
        let error = fixture.establish(8).expect_err("tampered");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
    }

    #[test]
    fn the_governing_trigger_is_the_greatest_entry_index_among_effective_ones() {
        let fixture = MirrorFixture::conformance();
        let anchored = fixture.establish(fixture.newest_tree_size()).expect("established");
        let (dataset, record) = fixture.record_f();
        let governing = governing_trigger(&anchored, &dataset, &record).expect("governs");
        // Entry 22 is the authorized retraction; entry 23 is a challenge by a non-authority
        // key, 32 and 33 carry non-verifying signatures, and 29 is co-signed by the authority.
        assert_eq!(governing.entry_index, 29);
        let codes: BTreeSet<&str> =
            governing.findings.iter().map(|finding| finding.code.as_str()).collect();
        assert!(codes.contains("trigger-anchored-as-challenge"));
        // A candidate whose signature does not verify never reaches trigger selection at all:
        // it is not a statement, so it is excluded when the verified view is built and
        // reported there instead.
        assert!(
            !codes.contains("trigger-signature-does-not-verify"),
            "an invalid signature is filtered before selection, not during it"
        );
        assert!(anchored.findings.iter().any(|f| f.code == "entry-is-not-a-statement"));
    }

    #[test]
    fn a_record_that_was_never_introduced_has_no_authority_to_trigger_it() {
        let fixture = MirrorFixture::conformance();
        let anchored = fixture.establish(8).expect("established");
        let error = governing_trigger(&anchored, "customers", "sha256:deadbeef")
            .expect_err("never introduced");
        assert!(error.to_string().contains("authority cannot predate"), "{error}");
    }

    #[test]
    fn a_record_with_no_effective_trigger_is_reported_as_such() {
        let fixture = MirrorFixture::conformance();
        let anchored = fixture.establish(8).expect("established");
        let (dataset, record) = fixture.record_b();
        let error = governing_trigger(&anchored, &dataset, &record).expect_err("no trigger");
        assert!(error.to_string().contains("no effective trigger"), "{error}");
    }

    #[test]
    fn a_consistency_proof_carrying_anything_but_family_strings_is_unusable_remote_evidence() {
        // Adaptor §8.3 serializes a consistency proof as a JSON array of `sha256:<hex>` family
        // strings and nothing else. Dropping the elements that are not — and certifying the
        // neighbour relationship on what is left — verifies a shorter proof than the one the
        // mirror served, which hands the mirror the choice of which proof gets checked.
        #[derive(Debug)]
        struct Serving(Value);
        impl Fetcher for Serving {
            fn fetch(&self, _request: &Request) -> Result<crate::net::Response, FetchFailure> {
                Ok(crate::net::Response {
                    status: 200,
                    body: serde_json::to_vec(&self.0).unwrap_or_default(),
                })
            }
        }

        let good = format!("sha256:{}", hex::encode([0x11_u8; 32]));
        let mirror_of = |path: Value| {
            let fetcher = Serving(json!({ "from": 8, "to": 13, "consistency_path": path }));
            (fetcher, ())
        };

        for (path, why) in [
            (json!([good.clone(), 42]), "a number is not a family string"),
            (json!([good.clone(), Value::Null]), "null is not a family string"),
            (json!([good.clone(), "sha512:beef"]), "another family is not this one"),
            (json!([good, "not-a-hash"]), "an unprefixed string is not one either"),
            (json!("sha256:deadbeef"), "the proof is an array, not a string"),
        ] {
            let (fetcher, ()) = mirror_of(path);
            let mirror = Mirror::new(
                &fetcher,
                crate::testing::MIRROR,
                crate::checkpoint::TEST_LOG_PROFILE,
                crate::policy::NetworkLimits::default(),
            )
            .expect("known profile");
            let error = mirror.consistency_path(8, 13).expect_err(why);
            assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable, "{why}: {error}");
        }

        // A conforming proof reads back exactly, in the order served.
        let (fetcher, ()) = mirror_of(json!([&good, &good]));
        let mirror = Mirror::new(
            &fetcher,
            crate::testing::MIRROR,
            crate::checkpoint::TEST_LOG_PROFILE,
            crate::policy::NetworkLimits::default(),
        )
        .expect("known profile");
        assert_eq!(mirror.consistency_path(8, 13).expect("conforming"), vec![good.clone(), good]);
    }

    #[test]
    fn retrieval_by_entry_id_is_content_checked_against_the_id_requested() {
        // Adaptor §10.1.1 verifier duty 1: recompute the digest and reject unless it equals the
        // requested id. That makes retrieval self-checking — a deployment cannot substitute a
        // different entry, and the bytes need not be trusted because of their source.
        let fixture = MirrorFixture::conformance();
        let mirror = Mirror::new(
            &fixture,
            crate::testing::MIRROR,
            crate::checkpoint::TEST_LOG_PROFILE,
            crate::policy::NetworkLimits::default(),
        )
        .expect("known profile");
        let identity = crate::testing::identity_at(&fixture, 8);

        let anchored = fixture.establish(8).expect("established");
        let envelope = anchored.statements.get(1).expect("committed");
        let entry_id = ahl_core::entry_id(envelope);
        assert_eq!(&mirror.entry_by_id(&entry_id, &identity).expect("retrieved"), envelope);

        // Absence is unavailability, never a negative result about the corpus.
        let error = mirror
            .entry_by_id(&format!("sha256:{}", "aa".repeat(32)), &identity)
            .expect_err("absent");
        assert!(error.to_string().contains("never a negative result"), "{error}");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
    }

    #[test]
    fn required_tree_roots_are_collected_before_traversal_begins() {
        let fixture = MirrorFixture::conformance();
        let anchored = fixture.establish(fixture.newest_tree_size()).expect("established");
        let roots = required_tree_roots(&anchored.statements);
        assert!(!roots.is_empty(), "the corpus commits batch and disposition trees");
        assert!(roots.values().all(|count| *count > 0));
    }

    // -- adaptor §7.4.1 and core §2.1, at the establishment boundary --------------------

    #[test]
    fn a_forged_later_manifest_can_never_authenticate_a_checkpoint() {
        // Blocker 1, staged end to end. A hostile mirror serves a recomputable tree carrying
        // the genuine pinned genesis manifest **plus** a forged later manifest naming attacker
        // log keys, and a checkpoint signed by those keys. The tree recomputes, the inclusion
        // proofs are real, and the forged manifest even links correctly to the version active
        // before it — so if governance were collected before it was authenticated, this would
        // authenticate.
        let fixture = MirrorFixture::conformance().with_forged_manifest();
        let size = fixture.forged_tree_size();

        let error = fixture.establish(size).expect_err("the forged chain must not authenticate");
        assert_eq!(
            error.outcome(),
            crate::outcome::Outcome::Unverifiable,
            "a hostile mirror disproves nothing about the user's artifact: {error}"
        );
        assert!(error.to_string().contains("does not verify"), "{error}");

        // And the forgery truncates nothing: a checkpoint below it still establishes, because
        // an unauthorized governance statement is ignored rather than treated as a fork of the
        // corpus (adaptor §7.4.1). That the forged manifest is *ignored and reported* rather
        // than fatal is pinned in `governance`'s own tests, over an enumeration that includes
        // it; this checkpoint's enumeration stops before it.
        let anchored = fixture.establish(8).expect("the honest prefix still establishes");
        assert_eq!(anchored.checkpoint.tree_size, 8);
    }

    #[test]
    fn a_voided_entry_cannot_establish_an_earlier_introduction() {
        // Blocker 2. A forged, non-verifying ingestion at a *smaller* index than the genuine
        // introduction would, if the raw enumeration were read, move the introduction — and
        // with it the authority consulted for a later, genuine trigger.
        let honest = ahl_core::TestKey::from_seed_hex("producer", &"01".repeat(32)).expect("seed");
        let attacker =
            ahl_core::TestKey::from_seed_hex("attacker", &"09".repeat(32)).expect("seed");
        let record = format!("sha256:{}", hex::encode([0xab_u8; 32]));

        let genesis = ahl_core::envelope(
            serde_json::json!({
                "type": "manifest",
                "keys": [ honest.producer_key_object() ],
                "log": conformant_log_object(),
                "datasets": { "d": { "commitment_mode": "plain",
                                     "authority": { "producer": "p", "key_ids": [honest.key_id()] } } },
            }),
            &honest,
        );
        let forged = ahl_core::envelope(
            serde_json::json!({ "type": "ingestion", "dataset": "d", "record": record }),
            &attacker,
        );
        let genuine = ahl_core::envelope(
            serde_json::json!({ "type": "ingestion", "dataset": "d", "record": record }),
            &honest,
        );
        let entries = vec![(0, genesis), (1, forged), (2, genuine)];
        let policy = ahl_core::receipt::TrustPolicy {
            genesis_entry_id: ahl_core::entry_id(&entries[0].1),
            genesis_key_ids: Some(std::collections::BTreeSet::from([honest.key_id()])),
            ..ahl_core::receipt::TrustPolicy::default()
        };
        let (governance, _) = Governance::resolve(&entries, &policy).expect("anchor holds");
        let (statements, findings) =
            Statements::build(&entries, &governance).expect("known statement types");

        assert_eq!(
            introduction_index(&statements, "d", &record),
            Some(2),
            "the forged ingestion at index 1 must not establish the introduction"
        );
        assert!(findings.iter().any(|finding| finding.code == "entry-is-not-a-statement"));
        assert_eq!(statements.statement_type(1), Some("not-a-statement"));
        // The position is occupied, never removed: the entry index is the ordering primitive.
        assert_eq!(statements.len(), 3);
    }

    #[test]
    fn a_duplicate_statement_id_is_void_from_the_second_occurrence_on() {
        // Blocker 3. Core §2.1: "if duplicates occur, the one with the smallest entry index
        // governs and later ones are void."
        let honest = ahl_core::TestKey::from_seed_hex("producer", &"01".repeat(32)).expect("seed");
        let genesis = ahl_core::envelope(
            serde_json::json!({
                "type": "manifest",
                "keys": [ honest.producer_key_object() ],
                "log": conformant_log_object(),
            }),
            &honest,
        );
        let payload =
            serde_json::json!({ "type": "ingestion", "dataset": "d", "record": "sha256:aa" });
        let first = ahl_core::envelope(payload.clone(), &honest);
        let second = ahl_core::envelope(payload, &honest);
        assert_eq!(
            ahl_core::statement_id(&first).expect("id"),
            ahl_core::statement_id(&second).expect("id"),
            "one payload, one statement id"
        );

        let entries = vec![(0, genesis), (4, first), (9, second)];
        let policy = ahl_core::receipt::TrustPolicy {
            genesis_entry_id: ahl_core::entry_id(&entries[0].1),
            genesis_key_ids: Some(std::collections::BTreeSet::from([honest.key_id()])),
            ..ahl_core::receipt::TrustPolicy::default()
        };
        let (governance, _) = Governance::resolve(&entries, &policy).expect("anchor holds");
        let (statements, findings) =
            Statements::build(&entries, &governance).expect("known statement types");

        assert_eq!(statements.statement_type(1), Some("ingestion"), "the smaller index governs");
        assert_eq!(statements.statement_type(2), Some("not-a-statement"), "the later one is void");
        assert!(findings.iter().any(|finding| finding.code == "statement-void-duplicate-id"));
    }

    #[test]
    fn a_non_verifying_duplicate_at_a_smaller_index_cannot_void_the_genuine_statement() {
        // The ordering between the two rules, which core §2.1 does not fix. Excluding
        // non-statements first is the only reading that is not trivially exploitable: an
        // attacker who could void a genuine statement by anchoring the same payload with a
        // broken signature at a smaller index would have a deletion primitive.
        let honest = ahl_core::TestKey::from_seed_hex("producer", &"01".repeat(32)).expect("seed");
        let attacker =
            ahl_core::TestKey::from_seed_hex("attacker", &"09".repeat(32)).expect("seed");
        let genesis = ahl_core::envelope(
            serde_json::json!({
                "type": "manifest",
                "keys": [ honest.producer_key_object() ],
                "log": conformant_log_object(),
            }),
            &honest,
        );
        let payload =
            serde_json::json!({ "type": "retraction", "dataset": "d", "record": "sha256:aa" });
        let forged_first = ahl_core::envelope(payload.clone(), &attacker);
        let genuine_later = ahl_core::envelope(payload, &honest);

        let entries = vec![(0, genesis), (1, forged_first), (2, genuine_later)];
        let policy = ahl_core::receipt::TrustPolicy {
            genesis_entry_id: ahl_core::entry_id(&entries[0].1),
            genesis_key_ids: Some(std::collections::BTreeSet::from([honest.key_id()])),
            ..ahl_core::receipt::TrustPolicy::default()
        };
        let (governance, _) = Governance::resolve(&entries, &policy).expect("anchor holds");
        let (statements, _) =
            Statements::build(&entries, &governance).expect("known statement types");

        assert_eq!(statements.statement_type(1), Some("not-a-statement"));
        assert_eq!(
            statements.statement_type(2),
            Some("retraction"),
            "the genuine statement survives a forged duplicate at a smaller index"
        );
    }
}
