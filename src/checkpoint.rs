//! Checkpoints: authentication, identity, and the equivocation floor.
//!
//! Two states are normative, and the distinction is where a plausible implementation goes
//! wrong (core spec §7.3, adaptor §6.6):
//!
//! * **authenticated** — the log signature verifies under the key set resolved from the
//!   *governing manifest version*, selected by `tree_size`. It establishes that the log signed
//!   those field values, and nothing about whether the tree they describe is the tree the
//!   verifier has entries for.
//! * **series-usable** — additionally, the root has been recomputed from held entries and the
//!   neighbouring consistency relationships verify.
//!
//! Stated the other way round: **authentication is enough to condemn, but not enough to
//! certify.** Divergence detection therefore runs over *every authenticated member*
//! ([`equivocation_floor`]), while promotion to series-usable is what [`crate::enumerate`]
//! performs.
//!
//! # Two signing forms
//!
//! The signed bytes are adaptor-defined and the two profiles this client meets disagree, so
//! the form is selected from the pinned profile id rather than guessed:
//!
//! * `ahl-test-log-v1` signs `JCS(checkpoint object with "signature" removed)`;
//! * `ahl-adaptor-atl-v1` signs the 98-byte ATL blob of §6.1, whose `checkpoint_time` must be
//!   the exact nine-fractional-digit UTC rendering of §6.3 — any rendering that loses
//!   precision makes the signature unverifiable, so a non-conforming rendering is rejected
//!   rather than reinterpreted.
//!
//! A profile this build does not know is a limitation of that profile, named as such, never a
//! silent fallback to whichever form happens to verify.

use std::collections::BTreeMap;

use ahl_core::{cosignature_bytes, decode_pubkey, verify_signature};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cache::CheckpointIdentity;
use crate::error::{CliError, CliResult};

/// The 18-byte ATL checkpoint magic (adaptor §6.1).
const ATL_MAGIC: &[u8; 18] = b"ATL-Protocol-v1-CP";
/// Length of the signed ATL blob.
const ATL_BLOB_LEN: usize = 98;

/// The profile id of the AHL conformance corpus's test adaptor.
pub const TEST_LOG_PROFILE: &str = "ahl-test-log-v1";
/// The profile id of the ATL adaptor profile.
pub const ATL_PROFILE: &str = "ahl-adaptor-atl-v1";

/// Which bytes the log signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningForm {
    /// `JCS(checkpoint object with "signature" removed)`.
    CanonicalJson,
    /// The 98-byte ATL blob of adaptor profile §6.1.
    AtlBlob,
}

impl SigningForm {
    /// Select the form the pinned profile defines.
    ///
    /// # Errors
    ///
    /// [`CliError::ProfileLimitation`] for a profile this build does not implement — named as
    /// a limitation of that profile, never a guess.
    pub fn for_profile(profile_id: &str) -> CliResult<Self> {
        match profile_id {
            TEST_LOG_PROFILE => Ok(Self::CanonicalJson),
            ATL_PROFILE => Ok(Self::AtlBlob),
            other => Err(CliError::ProfileLimitation(format!(
                "this build implements no checkpoint signing form for adaptor profile \
                 `{other}`; the signed bytes are adaptor-defined and are never guessed"
            ))),
        }
    }
}

/// A signed checkpoint object (core spec §1.2, receipt format §2, adaptor §6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// `"sha256:" || hex(origin)`.
    pub log_id: String,
    /// Number of entries committed: exactly `[0, tree_size)`.
    pub tree_size: u64,
    /// `"sha256:" || hex(root)`.
    pub root_hash: String,
    /// RFC 3339. Under `ahl-adaptor-atl-v1` this must carry exactly nine fractional digits.
    pub checkpoint_time: String,
    /// `key_id` of the signing key.
    pub key_id: String,
    /// `"base64:" || base64(raw 64-byte Ed25519 signature)`.
    pub signature: String,
}

impl Checkpoint {
    /// Parse from a JSON value, rejecting anything that is not a complete checkpoint object.
    ///
    /// # Errors
    ///
    /// [`CliError::EvidenceMissing`] — a checkpoint arriving from a server is a *remote
    /// candidate*, so a malformed one means usable evidence was not obtained, never that the
    /// user's artifact is disproved.
    pub fn from_value(value: &Value) -> CliResult<Self> {
        serde_json::from_value(value.clone()).map_err(|source| {
            CliError::EvidenceMissing(format!("checkpoint object is malformed: {source}"))
        })
    }

    /// The identity a claim binds on: `{log_id, tree_size, root_hash}`.
    ///
    /// Matching is on these fields, **not** byte-identity of the checkpoint object: a quiet log
    /// may legitimately publish several signed checkpoints at one size with the same root, and
    /// rejecting those would break honest deployments (§7).
    #[must_use]
    pub fn identity(&self) -> CheckpointIdentity {
        CheckpointIdentity {
            log_id: self.log_id.clone(),
            tree_size: self.tree_size,
            root_hash: self.root_hash.clone(),
        }
    }

    /// Whether this checkpoint has the same identity as `other`.
    #[must_use]
    pub fn matches_identity(&self, other: &CheckpointIdentity) -> bool {
        self.log_id == other.log_id
            && self.tree_size == other.tree_size
            && self.root_hash == other.root_hash
    }

    /// The bytes the log signed, under `form`.
    ///
    /// # Errors
    ///
    /// [`CliError::EvidenceMissing`] if a field cannot be rendered into the adaptor's form.
    pub fn signing_bytes(&self, form: SigningForm) -> CliResult<Vec<u8>> {
        match form {
            SigningForm::CanonicalJson => {
                let value = serde_json::to_value(self).map_err(|source| {
                    CliError::Internal(format!("cannot re-serialize a checkpoint: {source}"))
                })?;
                ahl_core::checkpoint_signing_bytes(&value).map_err(|source| {
                    CliError::EvidenceMissing(format!("checkpoint is not an object: {source}"))
                })
            }
            SigningForm::AtlBlob => self.atl_blob(),
        }
    }

    /// Assemble the 98-byte ATL blob of adaptor profile §6.1.
    ///
    /// # Errors
    ///
    /// [`CliError::EvidenceMissing`] if the origin, root or timestamp cannot be recovered
    /// exactly. A `checkpoint_time` that is not the §6.3 rendering is rejected rather than
    /// reinterpreted: any loss of precision makes the signature unverifiable.
    pub fn atl_blob(&self) -> CliResult<Vec<u8>> {
        let origin = raw_digest("log_id", &self.log_id)?;
        let root = raw_digest("root_hash", &self.root_hash)?;
        let nanos = parse_atl_time(&self.checkpoint_time)?;
        let mut blob = Vec::with_capacity(ATL_BLOB_LEN);
        blob.extend_from_slice(ATL_MAGIC);
        blob.extend_from_slice(&origin);
        blob.extend_from_slice(&self.tree_size.to_le_bytes());
        blob.extend_from_slice(&nanos.to_le_bytes());
        blob.extend_from_slice(&root);
        Ok(blob)
    }

    /// Verify the log signature against `keys`, resolved from the **governing manifest
    /// version** by the caller.
    ///
    /// # Errors
    ///
    /// [`CliError::EvidenceMissing`] when the key is unknown or the signature is unreadable.
    pub fn signature_verifies(
        &self,
        form: SigningForm,
        keys: &BTreeMap<String, String>,
    ) -> CliResult<bool> {
        let Some(pubkey) = keys.get(&self.key_id) else {
            return Ok(false);
        };
        let key = decode_pubkey(pubkey).map_err(|source| {
            CliError::EvidenceMissing(format!("manifest log key is unreadable: {source}"))
        })?;
        let bytes = self.signing_bytes(form)?;
        verify_signature(&key, &bytes, &self.signature).map_err(|source| {
            CliError::EvidenceMissing(format!("checkpoint signature is unreadable: {source}"))
        })
    }

    /// Verify a witness cosignature over this checkpoint (adaptor §11.1).
    ///
    /// The cosigned bytes bind the checkpoint **including its own `signature` member** plus the
    /// witness id, so a cosignature attests to a checkpoint the log actually signed and cannot
    /// be replayed for another witness.
    ///
    /// # Errors
    ///
    /// [`CliError::EvidenceMissing`] when the witness key is unreadable.
    pub fn cosignature_verifies(
        &self,
        witness_id: &str,
        cosignature: &str,
        pubkey: &str,
    ) -> CliResult<bool> {
        let key = decode_pubkey(pubkey).map_err(|source| {
            CliError::EvidenceMissing(format!("witness key is unreadable: {source}"))
        })?;
        let value = serde_json::to_value(self).map_err(|source| {
            CliError::Internal(format!("cannot re-serialize a checkpoint: {source}"))
        })?;
        verify_signature(&key, &cosignature_bytes(&value, witness_id), cosignature).map_err(
            |source| {
                CliError::EvidenceMissing(format!("witness cosignature is unreadable: {source}"))
            },
        )
    }
}

fn raw_digest(field: &'static str, value: &str) -> CliResult<[u8; 32]> {
    ahl_core::parse_hash_hex(value).map_err(|source| {
        CliError::EvidenceMissing(format!("checkpoint `{field}` is not a sha256 family string: {source}"))
    })
}

/// Parse the §6.3 rendering back to the exact u64 nanosecond value.
///
/// A `checkpoint_time` that is not `YYYY-MM-DDTHH:MM:SS.fffffffffZ` is rejected: the verifier
/// reconstructs the signed blob from the parsed object, and any rendering that loses precision
/// makes the signature unverifiable.
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] naming the rule the rendering broke.
pub fn parse_atl_time(value: &str) -> CliResult<u64> {
    let reject = |detail: &str| {
        CliError::EvidenceMissing(format!(
            "`checkpoint_time` `{value}` {detail}; adaptor profile §6.3 fixes exactly nine \
             fractional digits and a `Z` suffix"
        ))
    };
    let Some((seconds_part, fraction_part)) = value.split_once('.') else {
        return Err(reject("carries no fractional part"));
    };
    let Some(fraction) = fraction_part.strip_suffix('Z') else {
        return Err(reject("does not end in `Z`"));
    };
    if fraction.len() != 9 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return Err(reject("does not carry exactly nine fractional digits"));
    }
    let instant = crate::evaluation::parse_artifact_time("checkpoint_time", &format!("{seconds_part}Z"))
        .map_err(|_| reject("is not RFC 3339"))?;
    let seconds = u64::try_from(instant.unix_timestamp())
        .map_err(|_| reject("precedes the Unix epoch"))?;
    let nanos: u64 = fraction.parse().map_err(|_| reject("has an unparseable fractional part"))?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|s| s.checked_add(nanos))
        .ok_or_else(|| reject("overflows a nanosecond counter"))
}

/// The lowest `tree_size` at which two **authenticated** members carry different roots.
///
/// From that size the series is no longer canonical: no incorporation bound, enumeration
/// response or completeness claim may be grounded at or beyond it, while members below the
/// divergence remain usable. Choosing a branch is a conformance violation, so this function
/// reports the floor and never picks one.
///
/// The scope is deliberately *every authenticated member*, not the series-usable ones:
/// divergence is visible from checkpoint metadata alone, and requiring usability first would
/// let a deployment defer detection indefinitely by never recomputing the branch it dislikes
/// (adaptor §6.6.1).
#[must_use]
pub fn equivocation_floor(authenticated: &[Checkpoint]) -> Option<u64> {
    let mut roots: BTreeMap<u64, &str> = BTreeMap::new();
    let mut floor: Option<u64> = None;
    for checkpoint in authenticated {
        match roots.get(&checkpoint.tree_size) {
            Some(seen) if *seen != checkpoint.root_hash => {
                floor = Some(floor.map_or(checkpoint.tree_size, |at| at.min(checkpoint.tree_size)));
            }
            Some(_) => {}
            None => {
                roots.insert(checkpoint.tree_size, &checkpoint.root_hash);
            }
        }
    }
    floor
}

/// Verify an RFC 9162 consistency proof between two roots, through `atl-core`.
///
/// Never reimplemented locally: this is the anti-drift coupling with the ATL family.
///
/// # Errors
///
/// [`CliError::EvidenceMissing`] if the path or either root is unreadable.
pub fn consistency_verifies(
    from: &Checkpoint,
    to: &Checkpoint,
    path: &[String],
) -> CliResult<bool> {
    let unreadable =
        |what: &str| CliError::EvidenceMissing(format!("consistency proof {what} is unreadable"));
    let old_root = ahl_core::parse_hash_hex(&from.root_hash).map_err(|_| unreadable("from-root"))?;
    let new_root = ahl_core::parse_hash_hex(&to.root_hash).map_err(|_| unreadable("to-root"))?;
    let hashes = path
        .iter()
        .map(|hash| ahl_core::parse_hash_hex(hash))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| unreadable("path"))?;
    let proof = atl_core::core::merkle::ConsistencyProof {
        from_size: from.tree_size,
        to_size: to.tree_size,
        path: hashes,
    };
    atl_core::core::merkle::verify_consistency(&proof, &old_root, &new_root)
        .map_err(|source| CliError::EvidenceMissing(format!("consistency proof: {source}")))
}

#[cfg(test)]
mod tests {
    use ahl_core::TestKey;
    use serde_json::json;

    use super::*;

    fn key() -> TestKey {
        TestKey::from_seed_hex("log-1", &"03".repeat(32)).expect("seed")
    }

    fn keys() -> BTreeMap<String, String> {
        BTreeMap::from([(key().key_id(), key().pubkey())])
    }

    fn checkpoint(tree_size: u64, root: u8, time: &str) -> Checkpoint {
        Checkpoint {
            log_id: format!("sha256:{}", "11".repeat(32)),
            tree_size,
            root_hash: format!("sha256:{}", hex::encode([root; 32])),
            checkpoint_time: time.to_owned(),
            key_id: key().key_id(),
            signature: String::new(),
        }
    }

    fn signed(mut checkpoint: Checkpoint, form: SigningForm) -> Checkpoint {
        let bytes = checkpoint.signing_bytes(form).expect("signable");
        checkpoint.signature = key().sign(&bytes);
        checkpoint
    }

    #[test]
    fn the_signing_form_comes_from_the_pinned_profile_and_is_never_guessed() {
        assert_eq!(
            SigningForm::for_profile(TEST_LOG_PROFILE).expect("known"),
            SigningForm::CanonicalJson
        );
        assert_eq!(SigningForm::for_profile(ATL_PROFILE).expect("known"), SigningForm::AtlBlob);
        let error = SigningForm::for_profile("ahl-adaptor-rekor-v1").expect_err("unknown");
        assert!(matches!(error, CliError::ProfileLimitation(_)), "{error}");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
    }

    #[test]
    fn a_canonical_json_signature_verifies_and_a_tampered_field_does_not() {
        let cp = signed(checkpoint(8, 0xaa, "2026-08-16T12:00:00Z"), SigningForm::CanonicalJson);
        assert!(cp.signature_verifies(SigningForm::CanonicalJson, &keys()).expect("readable"));

        let mut tampered = cp;
        tampered.tree_size = 9;
        assert!(!tampered
            .signature_verifies(SigningForm::CanonicalJson, &keys())
            .expect("readable"));
    }

    #[test]
    fn an_atl_blob_signature_verifies_over_the_98_bytes_of_6_1() {
        let cp = checkpoint(1450, 0xbb, "2026-01-01T00:00:00.123456789Z");
        let blob = cp.atl_blob().expect("blob");
        assert_eq!(blob.len(), ATL_BLOB_LEN);
        assert_eq!(&blob[..18], ATL_MAGIC);
        assert_eq!(u64::from_le_bytes(blob[50..58].try_into().expect("8 bytes")), 1450);

        let signed = signed(cp, SigningForm::AtlBlob);
        assert!(signed.signature_verifies(SigningForm::AtlBlob, &keys()).expect("readable"));
        // The two forms sign different bytes, so a signature over one never validates the other.
        assert!(!signed
            .signature_verifies(SigningForm::CanonicalJson, &keys())
            .expect("readable"));
    }

    #[test]
    fn a_checkpoint_time_that_loses_precision_is_rejected_rather_than_reinterpreted() {
        for time in [
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00.123Z",
            "2026-01-01T00:00:00.123456789",
            "2026-01-01T00:00:00.12345678Z",
            "2026-01-01T00:00:00.1234567890Z",
            "2026-01-01T00:00:00.abcdefghiZ",
            "not-a-time.123456789Z",
        ] {
            assert!(parse_atl_time(time).is_err(), "`{time}` must be rejected");
        }
        assert_eq!(parse_atl_time("1970-01-01T00:00:00.000000001Z").expect("valid"), 1);
        assert_eq!(
            parse_atl_time("2026-01-01T00:00:00.123456789Z").expect("valid") % 1_000_000_000,
            123_456_789
        );
    }

    #[test]
    fn an_unknown_signing_key_fails_the_signature_rather_than_erroring() {
        let cp = signed(checkpoint(8, 0xaa, "2026-08-16T12:00:00Z"), SigningForm::CanonicalJson);
        assert!(!cp
            .signature_verifies(SigningForm::CanonicalJson, &BTreeMap::new())
            .expect("readable"));
    }

    #[test]
    fn identity_matching_is_on_three_fields_never_on_byte_identity() {
        let first = signed(checkpoint(8, 0xaa, "2026-08-16T12:00:00Z"), SigningForm::CanonicalJson);
        // A quiet log republishing at one size with the same root: a different object, the
        // same identity. Rejecting this would break honest deployments.
        let republished =
            signed(checkpoint(8, 0xaa, "2026-08-16T13:00:00Z"), SigningForm::CanonicalJson);
        assert_ne!(first, republished);
        assert!(republished.matches_identity(&first.identity()));

        let other_root =
            signed(checkpoint(8, 0xcc, "2026-08-16T12:00:00Z"), SigningForm::CanonicalJson);
        assert!(!other_root.matches_identity(&first.identity()));
    }

    #[test]
    fn the_equivocation_floor_is_the_lowest_diverging_size_not_the_newest() {
        let members = vec![
            checkpoint(4, 0x01, "2026-08-16T12:00:00Z"),
            checkpoint(8, 0x02, "2026-08-16T13:00:00Z"),
            checkpoint(8, 0x03, "2026-08-16T14:00:00Z"),
            checkpoint(12, 0x04, "2026-08-16T15:00:00Z"),
            checkpoint(12, 0x05, "2026-08-16T16:00:00Z"),
        ];
        assert_eq!(equivocation_floor(&members), Some(8));
    }

    #[test]
    fn republishing_at_one_size_with_one_root_is_a_tie_not_an_equivocation() {
        let members = vec![
            checkpoint(8, 0x02, "2026-08-16T13:00:00Z"),
            checkpoint(8, 0x02, "2026-08-16T14:00:00Z"),
        ];
        assert_eq!(equivocation_floor(&members), None);
        assert_eq!(equivocation_floor(&[]), None);
    }

    #[test]
    fn a_malformed_checkpoint_object_is_missing_evidence_not_a_verdict() {
        let error = Checkpoint::from_value(&json!({ "tree_size": 8 })).expect_err("incomplete");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
        assert!(Checkpoint::from_value(
            &serde_json::to_value(checkpoint(8, 0xaa, "t")).expect("value")
        )
        .is_ok());
    }

    #[test]
    fn a_cosignature_binds_the_signed_checkpoint_and_the_witness_identity() {
        let witness = TestKey::from_seed_hex("witness-1", &"04".repeat(32)).expect("seed");
        let cp = signed(checkpoint(8, 0xaa, "2026-08-16T12:00:00Z"), SigningForm::CanonicalJson);
        let value = serde_json::to_value(&cp).expect("value");
        let cosignature = witness.sign(&cosignature_bytes(&value, "witness-1"));

        assert!(cp
            .cosignature_verifies("witness-1", &cosignature, &witness.pubkey())
            .expect("readable"));
        // Replaying the same cosignature for another witness must fail.
        assert!(!cp
            .cosignature_verifies("witness-2", &cosignature, &witness.pubkey())
            .expect("readable"));
    }

    #[test]
    fn consistency_is_verified_through_atl_core_over_real_trees() {
        let leaves: Vec<Vec<u8>> = (0u8..8).map(|n| vec![n; 4]).collect();
        let hashes: Vec<_> = leaves.iter().map(|leaf| ahl_core::leaf_hash(leaf)).collect();
        let root_of = |n: usize| {
            format!("sha256:{}", hex::encode(atl_core::core::merkle::compute_root(&hashes[..n])))
        };
        let mut from = checkpoint(4, 0, "t");
        from.root_hash = root_of(4);
        let mut to = checkpoint(8, 0, "t");
        to.root_hash = root_of(8);

        let proof = atl_core::core::merkle::generate_consistency_proof(4, 8, |level, at| {
            if level == 0 {
                hashes.get(usize::try_from(at).ok()?).copied()
            } else {
                None
            }
        })
        .expect("proof");
        let path: Vec<String> =
            proof.path.iter().map(|hash| format!("sha256:{}", hex::encode(hash))).collect();

        assert!(consistency_verifies(&from, &to, &path).expect("readable"));
        // A proof for the wrong pair does not verify, and an unreadable one is reported.
        let mut wrong = to.clone();
        wrong.root_hash = root_of(6);
        assert!(!consistency_verifies(&from, &wrong, &path).expect("readable"));
        assert!(consistency_verifies(&from, &to, &["not-a-hash".to_owned()]).is_err());
    }

    #[test]
    fn a_checkpoint_with_an_unreadable_digest_reports_rather_than_panicking() {
        let mut cp = checkpoint(8, 0xaa, "2026-01-01T00:00:00.000000000Z");
        cp.log_id = "sha256:short".to_owned();
        assert!(cp.atl_blob().is_err());
        cp.log_id = format!("sha256:{}", "11".repeat(32));
        cp.root_hash = "not-a-digest".to_owned();
        assert!(cp.atl_blob().is_err());
    }
}
