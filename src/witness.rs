//! Witness cosignatures and refusal evidence.
//!
//! **Refusal evidence is a witness artifact, not an HTTP status.** A mirror's 404, 500, or
//! invented `reason` field is an operational failure and is reported as one; only a signed,
//! independently checkable witness refusal is refusal evidence.
//!
//! [`check_refusal`] runs adaptor profile §11.2.5 in order, and the order is normative:
//!
//! 1. the witness signature over `JCS(refusal object minus "signature")`;
//! 2. the log signature on **both** carried checkpoints — an unsigned or badly signed
//!    checkpoint proves nothing about the log — and both must carry the `log_id` the refusal
//!    names, which must be the corpus's bound Data Tree;
//! 3. the reason-specific recheck, with the proof's **pair binding** (§11.2.2) checked *before*
//!    consistency verification for `extension-failed`. Without that, a structurally valid proof
//!    that fails for some unrelated pair of sizes would validate a refusal about *this* pair —
//!    the failure would be real and the refusal would still be baseless. This was a defect in a
//!    first implementation of refusal checking.
//!
//! Per §11.2.3, `extension-failed` means exactly *the carried proof failed to verify*. It is
//! never reported as evidence that no valid extension exists: the proof the witness was given
//! may have been malformed, truncated, or generated against a different pair while a correct
//! proof for the same pair exists. The stronger conclusion belongs to `equivocation`, which is
//! self-contained.
//!
//! A refusal whose evidence does not support its declared reason is **unsupported**, and no
//! different reason the evidence *would* have supported is ever substituted.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::checkpoint::{consistency_verifies, Checkpoint, SigningForm};
use crate::error::{CliError, CliResult};
use crate::report::Finding;

/// The three reasons a verifier can independently recheck (adaptor §11.2.1).
///
/// `missing-consistency-proof` is **removed, not renamed** (§11.2.4): absence of a proof is not
/// independently verifiable from a signed refusal, so a witness could emit it at will and a
/// verifier could neither confirm nor refute it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// The offered checkpoint shares a `tree_size` with a cosigned one and carries a different
    /// `root_hash`. Self-contained: no append-only tree has two roots at one size.
    Equivocation,
    /// The offered `tree_size` is smaller than an already-cosigned size.
    SizeRegression,
    /// The carried purported extension proof fails verification — and nothing more.
    ExtensionFailed,
}

impl RefusalReason {
    fn parse(value: &str) -> CliResult<Self> {
        match value {
            "equivocation" => Ok(Self::Equivocation),
            "size-regression" => Ok(Self::SizeRegression),
            "extension-failed" => Ok(Self::ExtensionFailed),
            other => Err(CliError::EvidenceMissing(format!(
                "witness refusal declares reason `{other}`, which adaptor profile §11.2.1 does \
                 not define; `missing-consistency-proof` was removed, not renamed (§11.2.4)"
            ))),
        }
    }

    /// The stable finding code this reason is reported under.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Equivocation => "witness-refusal-equivocation",
            Self::SizeRegression => "witness-refusal-size-regression",
            Self::ExtensionFailed => "witness-refusal-extension-failed",
        }
    }
}

/// A refusal that verified in full, with the boundary of what it establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedRefusal {
    /// The reason the evidence supports.
    pub reason: RefusalReason,
    /// The witness that published it.
    pub witness_id: String,
    /// The retained checkpoint's `tree_size`.
    pub retained_size: u64,
    /// The offered checkpoint's `tree_size`.
    pub offered_size: u64,
    /// Findings raised while checking, reported alongside the result.
    pub findings: Vec<Finding>,
}

impl CheckedRefusal {
    /// The finding this refusal is reported as.
    #[must_use]
    pub fn finding(&self) -> Finding {
        let detail = match self.reason {
            RefusalReason::Equivocation => format!(
                "witness `{}` published verified equivocation evidence: the log signed two \
                 different roots at tree_size {}",
                self.witness_id, self.retained_size
            ),
            RefusalReason::SizeRegression => format!(
                "witness `{}` published verified size-regression evidence: the log offered \
                 tree_size {} after cosigning {}",
                self.witness_id, self.offered_size, self.retained_size
            ),
            // Never rendered as proof that no valid extension exists (§11.2.3).
            RefusalReason::ExtensionFailed => format!(
                "witness `{}` published verified extension-failed evidence: the proof the log \
                 carried from tree_size {} to {} failed to verify. This is a statement about \
                 the carried proof, not evidence that no valid extension exists",
                self.witness_id, self.retained_size, self.offered_size
            ),
        };
        Finding::new(self.reason.code(), detail)
    }
}

/// Check a witness refusal in full, per §11.2.5.
///
/// `witness_keys` are resolved by the caller from the manifest version governing the
/// checkpoints, or from locally trusted witness keys; `log_keys` likewise for the log.
/// `bound_log_id` is the corpus's bound Data Tree, which both carried checkpoints must name.
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] whenever any §11.2.5 check fails. Unusable remote material is
/// never a finding about the log: a refusal that does not verify tells a verifier nothing at
/// all, and is reported as evidence not obtained.
pub fn check_refusal(
    refusal: &Value,
    form: SigningForm,
    witness_keys: &BTreeMap<String, String>,
    log_keys: &BTreeMap<String, String>,
    bound_log_id: &str,
) -> CliResult<CheckedRefusal> {
    let unusable = |detail: String| {
        CliError::EvidenceMissing(format!("witness refusal is unusable: {detail}"))
    };

    if refusal.get("type").and_then(Value::as_str) != Some("witness-refusal") {
        return Err(unusable("`type` is not `witness-refusal`".to_owned()));
    }
    let witness_id = string(refusal, "witness_id").map_err(&unusable)?;
    let declared_log_id = string(refusal, "log_id").map_err(&unusable)?;
    let reason = RefusalReason::parse(&string(refusal, "reason").map_err(&unusable)?)?;

    // --- §11.2.5 step 1: the witness signature ----------------------------------------
    let key_id = string(refusal, "key_id").map_err(&unusable)?;
    let signature = string(refusal, "signature").map_err(&unusable)?;
    let pubkey = witness_keys.get(&key_id).ok_or_else(|| {
        unusable(format!("witness key `{key_id}` is not one this corpus declares"))
    })?;
    let signed_bytes = signing_bytes(refusal)?;
    let key = ahl_core::decode_pubkey(pubkey)
        .map_err(|source| unusable(format!("witness key is unreadable: {source}")))?;
    if !ahl_core::verify_signature(&key, &signed_bytes, &signature)
        .map_err(|source| unusable(format!("witness signature is unreadable: {source}")))?
    {
        return Err(unusable("the witness signature did not verify".to_owned()));
    }

    // --- §11.2.5 step 2: both carried checkpoints, log-signed and on the bound tree ----
    let retained = carried(refusal, "retained")?;
    let offered = carried(refusal, "offered")?;
    if declared_log_id != bound_log_id {
        return Err(unusable(format!(
            "the refusal names log `{declared_log_id}`, which is not the corpus's bound Data \
             Tree `{bound_log_id}`"
        )));
    }
    for (label, checkpoint) in [("retained", &retained), ("offered", &offered)] {
        if checkpoint.log_id != declared_log_id {
            return Err(unusable(format!(
                "the `{label}` checkpoint names log `{}`, the refusal names `{declared_log_id}`",
                checkpoint.log_id
            )));
        }
        if !checkpoint.signature_verifies(form, log_keys)? {
            return Err(unusable(format!(
                "the `{label}` checkpoint's log signature did not verify; an unsigned or badly \
                 signed checkpoint proves nothing about the log"
            )));
        }
    }

    // --- §11.2.5 step 3: the reason-specific recheck ----------------------------------
    let mut findings = Vec::new();
    let proof = carried_proof(refusal, &mut findings);
    match reason {
        RefusalReason::Equivocation | RefusalReason::SizeRegression => {
            // `proof` is REQUIRED for `extension-failed` and MUST be absent for the other two:
            // a carried proof that no reason directs a verifier to check is unverified
            // material inviting misreading (§11.2).
            if proof.is_some() {
                return Err(unusable(format!(
                    "reason `{}` carries a consistency proof, which §11.2 requires to be absent",
                    string(refusal, "reason").unwrap_or_default()
                )));
            }
        }
        RefusalReason::ExtensionFailed => {}
    }

    match reason {
        RefusalReason::Equivocation => {
            if retained.tree_size != offered.tree_size || retained.root_hash == offered.root_hash {
                return Err(unsupported(reason));
            }
        }
        RefusalReason::SizeRegression => {
            if offered.tree_size >= retained.tree_size {
                return Err(unsupported(reason));
            }
        }
        RefusalReason::ExtensionFailed => {
            let proof = proof.ok_or_else(|| {
                unusable(
                    "reason `extension-failed` carries no consistency proof, which §11.2 makes \
                     REQUIRED for it"
                        .to_owned(),
                )
            })?;
            // §11.2.2: the equalities are checked BEFORE running consistency verification, and
            // a failure is a rejection whether or not the proof then verifies.
            if proof.from_size != retained.tree_size || proof.to_size != offered.tree_size {
                return Err(unusable(format!(
                    "the carried proof covers sizes {}→{} but the refusal is about {}→{}; \
                     §11.2.2 binds the proof to the pair before it is verified",
                    proof.from_size, proof.to_size, retained.tree_size, offered.tree_size
                )));
            }
            // The refusal is supported only if the proof genuinely fails to verify.
            if consistency_verifies(&retained, &offered, &proof.path)? {
                return Err(unsupported(reason));
            }
        }
    }

    Ok(CheckedRefusal {
        reason,
        witness_id,
        retained_size: retained.tree_size,
        offered_size: offered.tree_size,
        findings,
    })
}

fn unsupported(reason: RefusalReason) -> CliError {
    CliError::EvidenceMissing(format!(
        "the carried evidence does not support the declared reason `{}`; a verifier never \
         substitutes a different reason the evidence would have supported (§11.2.5 step 3)",
        match reason {
            RefusalReason::Equivocation => "equivocation",
            RefusalReason::SizeRegression => "size-regression",
            RefusalReason::ExtensionFailed => "extension-failed",
        }
    ))
}

struct CarriedProof {
    from_size: u64,
    to_size: u64,
    path: Vec<String>,
}

/// Read the carried consistency proof.
///
/// Adaptor profile §11.2 names the member `proof`; `ahl-witness` serves it as
/// `consistency_proof`. Both are read, `proof` first, and using the alias raises a finding so
/// the disagreement is reported rather than smoothed over.
fn carried_proof(refusal: &Value, findings: &mut Vec<Finding>) -> Option<CarriedProof> {
    let (member, value) = match (refusal.get("proof"), refusal.get("consistency_proof")) {
        (Some(value), _) => ("proof", value),
        (None, Some(value)) => {
            findings.push(Finding::new(
                "witness-refusal-proof-member-alias",
                "the refusal carries its consistency proof as `consistency_proof`; adaptor \
                 profile §11.2 names the member `proof`",
            ));
            ("consistency_proof", value)
        }
        (None, None) => return None,
    };
    let _ = member;
    Some(CarriedProof {
        from_size: value.get("from_size")?.as_u64()?,
        to_size: value.get("to_size")?.as_u64()?,
        path: value
            .get("path")?
            .as_array()?
            .iter()
            .map(|hash| hash.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()?,
    })
}

fn carried(refusal: &Value, member: &str) -> CliResult<Checkpoint> {
    let value = refusal.get(member).ok_or_else(|| {
        CliError::EvidenceMissing(format!(
            "witness refusal carries no `{member}` checkpoint; §11.2 makes both REQUIRED in \
             every refusal"
        ))
    })?;
    Checkpoint::from_value(value)
}

fn string(value: &Value, member: &str) -> Result<String, String> {
    value
        .get(member)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("`{member}` is absent or not a string"))
}

/// `JCS(refusal object with "signature" removed)` — the same rule as a checkpoint, so one
/// signing routine serves both (§11.2).
fn signing_bytes(refusal: &Value) -> CliResult<Vec<u8>> {
    let mut object = refusal
        .as_object()
        .cloned()
        .ok_or_else(|| CliError::EvidenceMissing("witness refusal is not an object".to_owned()))?;
    object.remove("signature");
    Ok(ahl_core::jcs(&Value::Object(object)))
}

/// Verify a cosignature carried alongside a checkpoint, resolving the witness key.
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] when the key is unknown or the material is unreadable.
pub fn cosignature_holds(
    checkpoint: &Checkpoint,
    cosignature: &Value,
    witness_keys: &BTreeMap<String, String>,
) -> CliResult<bool> {
    let missing = |member: &str| {
        CliError::EvidenceMissing(format!("witness cosignature carries no `{member}`"))
    };
    let witness_id = cosignature
        .get("witness_id")
        .and_then(Value::as_str)
        .ok_or_else(|| missing("witness_id"))?;
    let key_id =
        cosignature.get("key_id").and_then(Value::as_str).ok_or_else(|| missing("key_id"))?;
    let signature = cosignature
        .get("cosignature")
        .and_then(Value::as_str)
        .ok_or_else(|| missing("cosignature"))?;
    let Some(pubkey) = witness_keys.get(key_id) else {
        return Ok(false);
    };
    checkpoint.cosignature_verifies(witness_id, signature, pubkey)
}

#[cfg(test)]
mod tests {
    use ahl_core::TestKey;
    use serde_json::json;

    use super::*;

    fn log_key() -> TestKey {
        TestKey::from_seed_hex("log-1", &"03".repeat(32)).expect("seed")
    }

    fn witness_key() -> TestKey {
        TestKey::from_seed_hex("witness-1", &"04".repeat(32)).expect("seed")
    }

    fn log_keys() -> BTreeMap<String, String> {
        BTreeMap::from([(log_key().key_id(), log_key().pubkey())])
    }

    fn witness_keys() -> BTreeMap<String, String> {
        BTreeMap::from([(witness_key().key_id(), witness_key().pubkey())])
    }

    const LOG_ID: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn signed_checkpoint(tree_size: u64, root: &str) -> Value {
        let mut cp = Checkpoint {
            log_id: LOG_ID.to_owned(),
            tree_size,
            root_hash: root.to_owned(),
            checkpoint_time: "2026-08-16T12:00:00Z".to_owned(),
            key_id: log_key().key_id(),
            signature: String::new(),
        };
        let bytes = cp.signing_bytes(SigningForm::CanonicalJson).expect("signable");
        cp.signature = log_key().sign(&bytes);
        serde_json::to_value(cp).expect("value")
    }

    fn root(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn sign_refusal(mut refusal: Value) -> Value {
        let bytes = signing_bytes(&refusal).expect("signable");
        refusal["signature"] = json!(witness_key().sign(&bytes));
        refusal
    }

    fn equivocation_refusal() -> Value {
        sign_refusal(json!({
            "type": "witness-refusal",
            "witness_id": "witness-1",
            "log_id": LOG_ID,
            "reason": "equivocation",
            "retained": signed_checkpoint(13, &root(0x01)),
            "offered": signed_checkpoint(13, &root(0x02)),
            "detail": "two roots at one tree size",
            "refused_at": "2026-08-16T12:00:00Z",
            "key_id": witness_key().key_id(),
        }))
    }

    fn check(refusal: &Value) -> CliResult<CheckedRefusal> {
        check_refusal(refusal, SigningForm::CanonicalJson, &witness_keys(), &log_keys(), LOG_ID)
    }

    #[test]
    fn a_verified_equivocation_refusal_is_reported_within_its_boundary() {
        let checked = check(&equivocation_refusal()).expect("verified");
        assert_eq!(checked.reason, RefusalReason::Equivocation);
        let finding = checked.finding();
        assert_eq!(finding.code, "witness-refusal-equivocation");
        assert!(finding.detail.contains("two different roots"));
    }

    #[test]
    fn a_tampered_witness_signature_makes_the_refusal_unusable() {
        let mut refusal = equivocation_refusal();
        refusal["detail"] = json!("rewritten after signing");
        let error = check(&refusal).expect_err("signature covers detail");
        assert!(error.to_string().contains("witness signature did not verify"), "{error}");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
    }

    #[test]
    fn an_unsigned_or_badly_signed_carried_checkpoint_proves_nothing_about_the_log() {
        let mut refusal = equivocation_refusal();
        refusal["offered"]["signature"] = json!(format!("base64:{}", "A".repeat(86) + "=="));
        let refusal = sign_refusal(refusal);
        let error = check(&refusal).expect_err("bad log signature");
        assert!(error.to_string().contains("proves nothing about the log"), "{error}");
    }

    #[test]
    fn a_refusal_about_another_log_is_refused() {
        let mut refusal = equivocation_refusal();
        refusal["log_id"] = json!(format!("sha256:{}", "99".repeat(32)));
        let refusal = sign_refusal(refusal);
        let error = check(&refusal).expect_err("wrong log");
        assert!(error.to_string().contains("bound Data Tree"), "{error}");
    }

    #[test]
    fn a_checkpoint_naming_a_different_log_than_the_refusal_is_refused() {
        let mut refusal = equivocation_refusal();
        refusal["offered"] = signed_checkpoint(13, &root(0x02));
        refusal["offered"]["log_id"] = json!(format!("sha256:{}", "99".repeat(32)));
        let refusal = sign_refusal(refusal);
        assert!(check(&refusal).is_err());
    }

    #[test]
    fn equivocation_evidence_that_does_not_show_two_roots_at_one_size_is_unsupported() {
        let mut refusal = equivocation_refusal();
        refusal["offered"] = signed_checkpoint(14, &root(0x02));
        let refusal = sign_refusal(refusal);
        let error = check(&refusal).expect_err("not equivocation");
        assert!(error.to_string().contains("does not support the declared reason"), "{error}");
        assert!(
            error.to_string().contains("never substitutes"),
            "a verifier must not silently reclassify: {error}"
        );
    }

    #[test]
    fn a_size_regression_refusal_is_checked_on_the_two_carried_sizes() {
        let good = sign_refusal(json!({
            "type": "witness-refusal", "witness_id": "witness-1", "log_id": LOG_ID,
            "reason": "size-regression",
            "retained": signed_checkpoint(20, &root(0x01)),
            "offered": signed_checkpoint(13, &root(0x02)),
            "detail": "", "refused_at": "2026-08-16T12:00:00Z",
            "key_id": witness_key().key_id(),
        }));
        assert_eq!(check(&good).expect("verified").reason, RefusalReason::SizeRegression);

        let bad = sign_refusal(json!({
            "type": "witness-refusal", "witness_id": "witness-1", "log_id": LOG_ID,
            "reason": "size-regression",
            "retained": signed_checkpoint(13, &root(0x01)),
            "offered": signed_checkpoint(20, &root(0x02)),
            "detail": "", "refused_at": "2026-08-16T12:00:00Z",
            "key_id": witness_key().key_id(),
        }));
        assert!(check(&bad).is_err());
    }

    /// Real trees, so `extension-failed` can be exercised against a genuine proof.
    fn real_roots() -> (String, String, Vec<String>) {
        let leaves: Vec<Vec<u8>> = (0u8..8).map(|n| vec![n; 4]).collect();
        let hashes: Vec<_> = leaves.iter().map(|leaf| ahl_core::leaf_hash(leaf)).collect();
        let root_of = |n: usize| {
            format!("sha256:{}", hex::encode(atl_core::core::merkle::compute_root(&hashes[..n])))
        };
        let proof = atl_core::core::merkle::generate_consistency_proof(4, 8, |level, at| {
            if level == 0 {
                hashes.get(usize::try_from(at).ok()?).copied()
            } else {
                None
            }
        })
        .expect("proof");
        let path = proof.path.iter().map(|h| format!("sha256:{}", hex::encode(h))).collect();
        (root_of(4), root_of(8), path)
    }

    fn extension_failed(
        from_size: u64,
        to_size: u64,
        path: &[String],
        offered_root: &str,
    ) -> Value {
        let (from_root, _, _) = real_roots();
        sign_refusal(json!({
            "type": "witness-refusal", "witness_id": "witness-1", "log_id": LOG_ID,
            "reason": "extension-failed",
            "retained": signed_checkpoint(4, &from_root),
            "offered": signed_checkpoint(8, offered_root),
            "proof": { "from_size": from_size, "to_size": to_size, "path": path },
            "detail": "", "refused_at": "2026-08-16T12:00:00Z",
            "key_id": witness_key().key_id(),
        }))
    }

    #[test]
    fn an_extension_failed_refusal_is_supported_only_when_the_carried_proof_really_fails() {
        let (_, _, path) = real_roots();
        // A genuinely failing proof: the offered root is not the tree the proof extends to.
        let checked = check(&extension_failed(4, 8, &path, &root(0xee))).expect("verified");
        assert_eq!(checked.reason, RefusalReason::ExtensionFailed);
        assert!(
            checked.finding().detail.contains("not evidence that no valid extension exists"),
            "§11.2.3 must be stated in the rendered finding"
        );

        // A proof that verifies: the refusal is baseless and is reported as unsupported.
        let (_, to_root, path) = real_roots();
        assert!(check(&extension_failed(4, 8, &path, &to_root)).is_err());
    }

    #[test]
    fn a_proof_for_an_unrelated_pair_of_sizes_does_not_validate_this_refusal() {
        // §11.2.2: the binding equalities are checked BEFORE verification, so a structurally
        // valid, genuinely failing proof for another pair is rejected rather than accepted.
        let (_, _, path) = real_roots();
        let error = check(&extension_failed(2, 6, &path, &root(0xee))).expect_err("unbound proof");
        assert!(error.to_string().contains("§11.2.2"), "{error}");
        assert!(error.to_string().contains("before it is verified"), "{error}");
    }

    #[test]
    fn extension_failed_without_a_proof_is_unusable() {
        let mut refusal = equivocation_refusal();
        refusal["reason"] = json!("extension-failed");
        let refusal = sign_refusal(refusal);
        let error = check(&refusal).expect_err("no proof");
        assert!(error.to_string().contains("REQUIRED"), "{error}");
    }

    #[test]
    fn a_proof_carried_by_a_reason_that_never_checks_one_is_refused() {
        let (_, _, path) = real_roots();
        let mut refusal = equivocation_refusal();
        refusal["proof"] = json!({ "from_size": 4, "to_size": 8, "path": path });
        let refusal = sign_refusal(refusal);
        let error = check(&refusal).expect_err("stray proof");
        assert!(error.to_string().contains("requires to be absent"), "{error}");
    }

    #[test]
    fn a_removed_or_unknown_reason_is_refused_by_name() {
        for reason in ["missing-consistency-proof", "inconsistent", "vibes"] {
            let mut refusal = equivocation_refusal();
            refusal["reason"] = json!(reason);
            let refusal = sign_refusal(refusal);
            let error = check(&refusal).expect_err("unknown reason");
            assert!(error.to_string().contains("§11.2.1"), "{error}");
        }
    }

    #[test]
    fn the_ahl_witness_proof_member_alias_is_accepted_and_reported() {
        let (_, _, path) = real_roots();
        let (from_root, _, _) = real_roots();
        let refusal = sign_refusal(json!({
            "type": "witness-refusal", "witness_id": "witness-1", "log_id": LOG_ID,
            "reason": "extension-failed",
            "retained": signed_checkpoint(4, &from_root),
            "offered": signed_checkpoint(8, &root(0xee)),
            "consistency_proof": { "from_size": 4, "to_size": 8, "path": path },
            "detail": "", "refused_at": "2026-08-16T12:00:00Z",
            "key_id": witness_key().key_id(),
        }));
        let checked = check(&refusal).expect("verified");
        assert!(checked
            .findings
            .iter()
            .any(|finding| finding.code == "witness-refusal-proof-member-alias"));
    }

    #[test]
    fn a_refusal_missing_a_carried_checkpoint_is_unusable() {
        let mut refusal = equivocation_refusal();
        refusal.as_object_mut().expect("object").remove("offered");
        let refusal = sign_refusal(refusal);
        let error = check(&refusal).expect_err("no offered checkpoint");
        assert!(error.to_string().contains("REQUIRED in every refusal"), "{error}");
    }

    #[test]
    fn a_refusal_signed_by_an_undeclared_witness_key_is_unusable() {
        let refusal = equivocation_refusal();
        let error = check_refusal(
            &refusal,
            SigningForm::CanonicalJson,
            &BTreeMap::new(),
            &log_keys(),
            LOG_ID,
        )
        .expect_err("unknown witness");
        assert!(error.to_string().contains("not one this corpus declares"), "{error}");
    }

    #[test]
    fn structurally_wrong_refusals_are_refused_rather_than_partially_read() {
        for refusal in [
            json!("not an object"),
            json!({ "type": "something-else" }),
            json!({ "type": "witness-refusal" }),
        ] {
            assert!(check(&refusal).is_err());
        }
    }

    #[test]
    fn a_cosignature_is_resolved_against_the_declared_witness_keys() {
        let cp = Checkpoint::from_value(&signed_checkpoint(8, &root(0x01))).expect("checkpoint");
        let value = serde_json::to_value(&cp).expect("value");
        let cosignature = json!({
            "witness_id": "witness-1",
            "key_id": witness_key().key_id(),
            "cosignature": witness_key().sign(&ahl_core::cosignature_bytes(
                &ahl_core::CosignedCheckpoint::project(&value).expect("cosignable"),
                "witness-1",
            )),
            "cosigned_at": "2026-08-16T12:00:00Z",
        });
        assert!(cosignature_holds(&cp, &cosignature, &witness_keys()).expect("readable"));
        // An undeclared witness key is not a cosignature failure to adjudicate: it simply does
        // not raise assurance.
        assert!(!cosignature_holds(&cp, &cosignature, &BTreeMap::new()).expect("readable"));
        assert!(cosignature_holds(&cp, &json!({}), &witness_keys()).is_err());
    }
}
