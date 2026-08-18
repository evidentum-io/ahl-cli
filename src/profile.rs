//! Adaptor profiles are content-addressed, and resolved from local possession only.
//!
//! A profile is accepted only if the bytes at the policy path hash to the policy entry. The
//! digest is recomputed over the artifact held — never trusted from any value carried with it
//! — because the pair `{id, digest}` is the whole of what a corpus pins (adaptor profile §14).
//!
//! Three distinct outcomes, and they are deliberately not one:
//!
//! * policy has no entry for the id → the profile is **not locally possessed**: unverifiable
//!   (`3`), never a fetch-and-trust and never "invalid";
//! * policy has an entry but the document is unreadable, or its bytes do not hash to the
//!   pinned value → the **local configuration is broken** (`2`), and nothing about the
//!   artifact has been shown;
//! * the document resolves → verification proceeds under the capabilities it declares.

use std::collections::BTreeMap;

use ahl_core::sha256_hex;

use crate::error::{CliError, CliResult};
use crate::policy::{ConfiguredProfile, LoadedPolicy};
use crate::secure;

/// Byte cap on an adaptor profile document.
const PROFILE_CAP: usize = 8 << 20;

/// A resolved profile: the id, the digest recomputed over the held bytes, and its size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProfile {
    /// The profile id, as pinned.
    pub id: String,
    /// The digest recomputed over the held document.
    pub hash: String,
    /// Bytes of the held document, for the record.
    pub size: usize,
}

/// Resolve one profile by id against local possession.
///
/// # Errors
///
/// [`CliError::ProfileNotPossessed`] when policy configures no such profile;
/// [`CliError::ProfileBroken`] when the configured document is unreadable or its digest does
/// not match the pinned value.
pub fn resolve(policy: &LoadedPolicy, id: &str) -> CliResult<ResolvedProfile> {
    let configured = policy
        .profiles
        .get(id)
        .ok_or_else(|| CliError::ProfileNotPossessed { id: id.to_owned() })?;
    resolve_configured(id, configured)
}

fn resolve_configured(id: &str, configured: &ConfiguredProfile) -> CliResult<ResolvedProfile> {
    let bytes = secure::read_regular("adaptor profile", &configured.path, PROFILE_CAP).map_err(
        |source| CliError::ProfileBroken {
            id: id.to_owned(),
            path: configured.path.display().to_string(),
            detail: source.to_string(),
        },
    )?;
    let computed = sha256_hex(&bytes);
    if computed != configured.hash {
        return Err(CliError::ProfileBroken {
            id: id.to_owned(),
            path: configured.path.display().to_string(),
            detail: format!(
                "document hashes to {computed}, policy pins {}",
                configured.hash
            ),
        });
    }
    Ok(ResolvedProfile { id: id.to_owned(), hash: computed, size: bytes.len() })
}

/// Resolve every configured profile, so a broken local configuration is reported before any
/// artifact is examined rather than only when one happens to reference it.
///
/// # Errors
///
/// The first [`CliError::ProfileBroken`] encountered, in profile-id order.
pub fn resolve_all(policy: &LoadedPolicy) -> CliResult<BTreeMap<String, ResolvedProfile>> {
    policy
        .profiles
        .iter()
        .map(|(id, configured)| Ok((id.clone(), resolve_configured(id, configured)?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use super::*;

    fn policy_with(dir: &Path, entries: &str) -> LoadedPolicy {
        let text = format!(
            "[policy]\n\
             genesis_entry_id = \"sha256:{}\"\n\
             genesis_key_ids = [\"sha256:{}\"]\n{entries}",
            "aa".repeat(32),
            "bb".repeat(32),
        );
        let path = dir.join("policy.toml");
        std::fs::write(&path, text).expect("write policy");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
        crate::policy::load(&path).expect("valid policy")
    }

    #[test]
    fn a_document_matching_its_pinned_digest_resolves() {
        let dir = tempfile::tempdir().expect("tempdir");
        let document = b"# adaptor profile\n";
        std::fs::write(dir.path().join("p.md"), document).expect("write profile");
        let hash = sha256_hex(document);
        let policy = policy_with(
            dir.path(),
            &format!("[policy.adaptor_profiles.p]\nhash = \"{hash}\"\npath = \"p.md\"\n"),
        );
        let resolved = resolve(&policy, "p").expect("resolves");
        assert_eq!(resolved.hash, hash);
        assert_eq!(resolved.size, document.len());
    }

    #[test]
    fn an_unconfigured_profile_is_not_locally_possessed_not_invalid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = policy_with(dir.path(), "");
        let error = resolve(&policy, "ahl-adaptor-atl-v1").expect_err("not possessed");
        assert!(matches!(error, CliError::ProfileNotPossessed { .. }), "{error}");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Unverifiable);
    }

    #[test]
    fn a_digest_mismatch_is_a_broken_local_configuration_not_a_verdict() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("p.md"), b"tampered").expect("write profile");
        let policy = policy_with(
            dir.path(),
            &format!(
                "[policy.adaptor_profiles.p]\nhash = \"sha256:{}\"\npath = \"p.md\"\n",
                "cc".repeat(32)
            ),
        );
        let error = resolve(&policy, "p").expect_err("digest mismatch");
        assert!(matches!(error, CliError::ProfileBroken { .. }), "{error}");
        assert_eq!(error.outcome(), crate::outcome::Outcome::Error);
    }

    #[test]
    fn an_unreadable_configured_document_is_also_a_broken_configuration() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = policy_with(
            dir.path(),
            &format!(
                "[policy.adaptor_profiles.p]\nhash = \"sha256:{}\"\npath = \"absent.md\"\n",
                "cc".repeat(32)
            ),
        );
        let error = resolve(&policy, "p").expect_err("absent document");
        assert!(matches!(error, CliError::ProfileBroken { .. }), "{error}");
    }

    #[test]
    fn resolve_all_reports_a_broken_configuration_before_any_artifact_is_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let document = b"ok\n";
        std::fs::write(dir.path().join("good.md"), document).expect("write");
        let policy = policy_with(
            dir.path(),
            &format!(
                "[policy.adaptor_profiles.good]\nhash = \"{}\"\npath = \"good.md\"\n\
                 [policy.adaptor_profiles.bad]\nhash = \"sha256:{}\"\npath = \"absent.md\"\n",
                sha256_hex(document),
                "cc".repeat(32),
            ),
        );
        assert!(resolve_all(&policy).is_err());

        let policy = policy_with(
            dir.path(),
            &format!(
                "[policy.adaptor_profiles.good]\nhash = \"{}\"\npath = \"good.md\"\n",
                sha256_hex(document)
            ),
        );
        assert_eq!(resolve_all(&policy).expect("all resolve").len(), 1);
    }
}
