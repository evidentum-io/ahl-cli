//! The local trust policy, and the three kinds of input the boundaries between them define.
//!
//! **Trusted — `[policy]`.** Exactly the fields of [`ahl_core::receipt::TrustPolicy`]:
//! `genesis_entry_id`, `genesis_key_ids`, `adaptor_profiles`, `trusted_witness_key_ids`,
//! `limits`. Operator-configured, never derived from an artifact. A missing
//! `genesis_entry_id` is a configuration error, never an accept.
//!
//! **Trusted only as secrets, held apart — `[policy.dataset_keys]`.** HMAC keys whose entire
//! purpose is that unauthorized parties cannot compute the commitment. Read from a separate
//! secret source by default; an inline `hex` value is permitted because the policy file
//! itself is opened under the same §4 rules a key file is (see [`crate::secure::read_secret`]).
//!
//! **Untrusted — `[endpoints]`.** Mirror and witness URLs. These are *addresses, not
//! authorities*: no trust follows from configuring one, and neither `log_id` nor a profile id
//! derives an endpoint. They live outside `[policy]` deliberately — reading a URL must never
//! look like reading a trust anchor.
//!
//! Relative paths inside the file resolve against the **policy file's own directory**, so a
//! policy and the material it pins move together.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ahl_core::receipt::{AdaptorCapabilities, AdaptorProfile, Limits, TrustPolicy};
use serde::Deserialize;
use zeroize::Zeroize as _;

use crate::error::{CliError, CliResult};
use crate::secure;

/// Byte cap on the policy file itself.
const POLICY_FILE_CAP: usize = 1 << 20;
/// Byte cap on a dataset-key file: a hex-encoded 32-byte key plus whitespace.
const KEY_FILE_CAP: usize = 1 << 12;

/// Network limits (design note §7). Separate from [`Limits`], which bounds *receipt* work and
/// has no network dimension at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkLimits {
    /// Maximum bytes accepted from one response, counted **after decompression**.
    pub max_response_bytes: u64,
    /// Maximum bytes accepted across the whole operation.
    pub max_total_bytes: u64,
    /// Maximum number of subrange requests one enumeration may issue.
    pub max_subrange_requests: u32,
    /// Maximum number of entries one enumeration may accept.
    pub max_entries: u64,
    /// Wall-clock budget for the whole operation, in seconds.
    pub wall_clock_seconds: u64,
}

impl Default for NetworkLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: 32 << 20,
            max_total_bytes: 256 << 20,
            max_subrange_requests: 256,
            max_entries: 1 << 20,
            wall_clock_seconds: 300,
        }
    }
}

/// Bounds on local files and local traversal, so a hostile file cannot exhaust memory where a
/// hostile server cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalLimits {
    /// Maximum bytes read from any one local file.
    pub max_file_bytes: usize,
    /// Maximum number of envelopes a local corpus may contain.
    pub max_corpus_entries: usize,
}

impl Default for LocalLimits {
    fn default() -> Self {
        Self { max_file_bytes: 32 << 20, max_corpus_entries: 1 << 20 }
    }
}

/// Where a mirror and a witness may be reached. Addresses, never authorities.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Endpoints {
    /// Base URL of a mirror serving retrieval, enumeration and checkpoints.
    pub mirror: Option<String>,
    /// Base URL of a witness serving cosigned checkpoints and refusal evidence.
    pub witness: Option<String>,
}

/// A configured adaptor profile: where the document is, and what it must hash to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredProfile {
    /// The pinned digest, as `sha256:<hex>`.
    pub hash: String,
    /// Local path to the profile document.
    pub path: PathBuf,
    /// What the document defines.
    pub capabilities: AdaptorCapabilities,
}

/// A loaded policy: the trust anchor, the endpoints, and the limits.
///
/// Dataset-key bytes inside `trust` are wiped when this value is dropped. They cannot be held
/// in a zeroizing container across the [`TrustPolicy`] boundary, which types them as a plain
/// `Vec<u8>`; wiping on drop is what this crate can guarantee without editing its sibling.
#[derive(Debug, Clone)]
pub struct LoadedPolicy {
    /// The trust policy `ahl-core` verifies against.
    pub trust: TrustPolicy,
    /// Profiles as configured, before resolution against their bytes.
    pub profiles: BTreeMap<String, ConfiguredProfile>,
    /// Untrusted locations.
    pub endpoints: Endpoints,
    /// Network limits.
    pub network: NetworkLimits,
    /// Local-file and traversal limits.
    pub local: LocalLimits,
}

impl Drop for LoadedPolicy {
    fn drop(&mut self) {
        for bytes in self.trust.dataset_keys.values_mut() {
            bytes.zeroize();
        }
    }
}

// ---------------------------------------------------------------------------
// Wire form
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    policy: PolicySection,
    #[serde(default)]
    endpoints: EndpointsSection,
    #[serde(default)]
    limits: LimitsSection,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicySection {
    genesis_entry_id: String,
    genesis_key_ids: Vec<String>,
    #[serde(default)]
    trusted_witness_key_ids: Vec<String>,
    #[serde(default)]
    adaptor_profiles: BTreeMap<String, ProfileSection>,
    #[serde(default)]
    dataset_keys: BTreeMap<String, DatasetKeySection>,
    #[serde(default)]
    limits: Option<ReceiptLimitsSection>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileSection {
    hash: String,
    path: String,
    #[serde(default)]
    checkpoint_raw: bool,
    #[serde(default)]
    consistency_proofs: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DatasetKeySection {
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    hex: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptLimitsSection {
    #[serde(default)]
    max_depth: Option<usize>,
    #[serde(default)]
    max_embedded: Option<usize>,
    #[serde(default)]
    max_decoded_bytes: Option<usize>,
    #[serde(default)]
    max_work_units: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointsSection {
    #[serde(default)]
    mirror: Option<String>,
    #[serde(default)]
    witness: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsSection {
    #[serde(default)]
    network: Option<NetworkLimitsSection>,
    #[serde(default)]
    local: Option<LocalLimitsSection>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkLimitsSection {
    #[serde(default)]
    max_response_bytes: Option<u64>,
    #[serde(default)]
    max_total_bytes: Option<u64>,
    #[serde(default)]
    max_subrange_requests: Option<u32>,
    #[serde(default)]
    max_entries: Option<u64>,
    #[serde(default)]
    wall_clock_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalLimitsSection {
    #[serde(default)]
    max_file_bytes: Option<usize>,
    #[serde(default)]
    max_corpus_entries: Option<usize>,
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

fn require_family_string(field: &str, value: &str) -> CliResult<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(CliError::Policy(format!(
            "`{field}` must be a `sha256:<hex>` family string, got `{value}`"
        )));
    };
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return Err(CliError::Policy(format!(
            "`{field}` must carry 64 lowercase hex digits, got `{value}`"
        )));
    }
    Ok(())
}

fn check_endpoint(what: &str, url: &str) -> CliResult<()> {
    if url.starts_with("https://") || url.starts_with("http://") {
        Ok(())
    } else {
        Err(CliError::Policy(format!(
            "`endpoints.{what}` must be an `https://` URL (or `http://` to a loopback peer), \
             got `{url}`"
        )))
    }
}

fn resolve_relative(base: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

fn decode_dataset_key(dataset: &str, text: &str) -> CliResult<Vec<u8>> {
    let trimmed = text.trim();
    let bytes = hex::decode(trimmed).map_err(|_| {
        // The value itself is never echoed: it is a secret.
        CliError::Policy(format!("dataset key for `{dataset}` is not hex"))
    })?;
    if bytes.len() != 32 {
        return Err(CliError::Policy(format!(
            "dataset key for `{dataset}` decodes to {} bytes, expected 32",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Load and validate a policy file.
///
/// The file is opened under the §4 secret rules: regular file, owner-only, owned by the
/// effective uid, symlinked final component refused. A hostile filesystem swapping a policy
/// for one anchored to an attacker corpus is the attack that closes.
///
/// # Errors
///
/// [`CliError::Open`] if the handle checks fail; [`CliError::Policy`] if the file does not
/// parse or is internally inconsistent.
pub fn load(path: &Path) -> CliResult<LoadedPolicy> {
    let bytes = secure::read_secret("trust policy", path, POLICY_FILE_CAP)?;
    let text = String::from_utf8(bytes)
        .map_err(|_| CliError::Policy("policy file is not valid UTF-8".to_owned()))?;
    let file: PolicyFile = toml::from_str(&text)
        .map_err(|source| CliError::Policy(format!("cannot parse policy: {source}")))?;

    let base = path.parent().unwrap_or(Path::new("."));
    from_parsed(file, base)
}

fn from_parsed(file: PolicyFile, base: &Path) -> CliResult<LoadedPolicy> {
    require_family_string("policy.genesis_entry_id", &file.policy.genesis_entry_id)?;
    if file.policy.genesis_key_ids.is_empty() {
        return Err(CliError::Policy(
            "`policy.genesis_key_ids` is empty; the genesis key fingerprints are a trust anchor \
             and are never defaulted from the artifact under verification"
                .to_owned(),
        ));
    }
    let mut genesis_key_ids = BTreeSet::new();
    for key_id in &file.policy.genesis_key_ids {
        require_family_string("policy.genesis_key_ids", key_id)?;
        genesis_key_ids.insert(key_id.clone());
    }
    let mut trusted_witness_key_ids = BTreeSet::new();
    for key_id in &file.policy.trusted_witness_key_ids {
        require_family_string("policy.trusted_witness_key_ids", key_id)?;
        trusted_witness_key_ids.insert(key_id.clone());
    }

    let mut profiles = BTreeMap::new();
    let mut adaptor_profiles = BTreeMap::new();
    for (id, section) in file.policy.adaptor_profiles {
        require_family_string("policy.adaptor_profiles.<id>.hash", &section.hash)?;
        let capabilities = AdaptorCapabilities {
            checkpoint_raw: section.checkpoint_raw,
            consistency_proofs: section.consistency_proofs,
        };
        adaptor_profiles.insert(
            id.clone(),
            AdaptorProfile { hash: section.hash.clone(), capabilities },
        );
        profiles.insert(
            id,
            ConfiguredProfile {
                hash: section.hash,
                path: resolve_relative(base, &section.path),
                capabilities,
            },
        );
    }

    let mut dataset_keys = BTreeMap::new();
    for (dataset, section) in file.policy.dataset_keys {
        let key = match (section.file, section.hex) {
            (Some(_), Some(_)) => {
                return Err(CliError::Policy(format!(
                    "dataset key for `{dataset}` names both `file` and `hex`; pick one"
                )))
            }
            (None, None) => {
                return Err(CliError::Policy(format!(
                    "dataset key for `{dataset}` names neither `file` nor `hex`"
                )))
            }
            (Some(file_path), None) => {
                let resolved = resolve_relative(base, &file_path);
                let mut raw = secure::read_secret("dataset key", &resolved, KEY_FILE_CAP)?;
                let decoded = String::from_utf8(raw.clone())
                    .map_err(|_| {
                        CliError::Policy(format!("dataset key for `{dataset}` is not valid UTF-8"))
                    })
                    .and_then(|text| decode_dataset_key(&dataset, &text));
                raw.zeroize();
                decoded?
            }
            (None, Some(mut inline)) => {
                let decoded = decode_dataset_key(&dataset, &inline);
                inline.zeroize();
                decoded?
            }
        };
        dataset_keys.insert(dataset, key);
    }

    let default_limits = Limits::default();
    let limits = file.policy.limits.map_or(default_limits, |section| Limits {
        max_depth: section.max_depth.unwrap_or(default_limits.max_depth),
        max_embedded: section.max_embedded.unwrap_or(default_limits.max_embedded),
        max_decoded_bytes: section.max_decoded_bytes.unwrap_or(default_limits.max_decoded_bytes),
        max_work_units: section.max_work_units.unwrap_or(default_limits.max_work_units),
    });

    if let Some(url) = &file.endpoints.mirror {
        check_endpoint("mirror", url)?;
    }
    if let Some(url) = &file.endpoints.witness {
        check_endpoint("witness", url)?;
    }

    let defaults = NetworkLimits::default();
    let network = file.limits.network.map_or(defaults, |section| NetworkLimits {
        max_response_bytes: section.max_response_bytes.unwrap_or(defaults.max_response_bytes),
        max_total_bytes: section.max_total_bytes.unwrap_or(defaults.max_total_bytes),
        max_subrange_requests: section
            .max_subrange_requests
            .unwrap_or(defaults.max_subrange_requests),
        max_entries: section.max_entries.unwrap_or(defaults.max_entries),
        wall_clock_seconds: section.wall_clock_seconds.unwrap_or(defaults.wall_clock_seconds),
    });

    let local_defaults = LocalLimits::default();
    let local = file.limits.local.map_or(local_defaults, |section| LocalLimits {
        max_file_bytes: section.max_file_bytes.unwrap_or(local_defaults.max_file_bytes),
        max_corpus_entries: section
            .max_corpus_entries
            .unwrap_or(local_defaults.max_corpus_entries),
    });

    Ok(LoadedPolicy {
        trust: TrustPolicy {
            genesis_entry_id: file.policy.genesis_entry_id,
            genesis_key_ids,
            adaptor_profiles,
            dataset_keys,
            trusted_witness_key_ids,
            limits,
        },
        profiles,
        endpoints: Endpoints {
            mirror: file.endpoints.mirror,
            witness: file.endpoints.witness,
        },
        network,
        local,
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    const GENESIS: &str =
        "sha256:be129d9d262de65c47eaad8d978ef54e87d5e1388182df53e036102816210a49";
    const KEY_ID: &str =
        "sha256:34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e";

    fn minimal() -> String {
        format!(
            "[policy]\ngenesis_entry_id = \"{GENESIS}\"\ngenesis_key_ids = [\"{KEY_ID}\"]\n"
        )
    }

    fn write_policy(dir: &Path, text: &str) -> PathBuf {
        let path = dir.join("policy.toml");
        std::fs::write(&path, text).expect("write policy");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only");
        path
    }

    #[test]
    fn a_minimal_policy_loads_with_the_documented_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_policy(dir.path(), &minimal());
        let loaded = load(&path).expect("valid policy");
        assert_eq!(loaded.trust.genesis_entry_id, GENESIS);
        assert_eq!(loaded.trust.limits, Limits::default());
        assert_eq!(loaded.network, NetworkLimits::default());
        assert_eq!(loaded.local, LocalLimits::default());
        assert_eq!(loaded.endpoints, Endpoints::default());
    }

    #[test]
    fn a_world_readable_policy_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, minimal()).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("mode");
        assert!(load(&path).is_err());
    }

    #[test]
    fn a_missing_genesis_anchor_is_a_configuration_error_never_an_accept() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_policy(dir.path(), "[policy]\ngenesis_key_ids = []\n");
        let error = load(&path).expect_err("no genesis anchor");
        assert!(matches!(error, CliError::Policy(_)), "{error}");
    }

    #[test]
    fn an_empty_genesis_key_set_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let text = format!("[policy]\ngenesis_entry_id = \"{GENESIS}\"\ngenesis_key_ids = []\n");
        let path = write_policy(dir.path(), &text);
        let error = load(&path).expect_err("empty key set");
        assert!(error.to_string().contains("never defaulted"), "{error}");
    }

    #[test]
    fn family_strings_are_validated_by_shape() {
        let dir = tempfile::tempdir().expect("tempdir");
        for anchor in ["not-a-digest", "sha256:XYZ", "sha256:00", "md5:aa"] {
            let text =
                format!("[policy]\ngenesis_entry_id = \"{anchor}\"\ngenesis_key_ids = [\"{KEY_ID}\"]\n");
            let path = write_policy(dir.path(), &text);
            assert!(load(&path).is_err(), "`{anchor}` must be refused");
        }
    }

    #[test]
    fn an_unknown_key_is_refused_rather_than_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let text = format!("{}surprise = true\n", minimal());
        let path = write_policy(dir.path(), &text);
        assert!(load(&path).is_err());
    }

    #[test]
    fn profile_paths_resolve_against_the_policy_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let text = format!(
            "{}\n[policy.adaptor_profiles.ahl-test-log-v1]\nhash = \"{GENESIS}\"\n\
             path = \"adaptor/profile.md\"\n",
            minimal()
        );
        let path = write_policy(dir.path(), &text);
        let loaded = load(&path).expect("valid policy");
        let profile = loaded.profiles.get("ahl-test-log-v1").expect("configured");
        assert_eq!(profile.path, dir.path().join("adaptor/profile.md"));
        assert!(!profile.capabilities.checkpoint_raw);
        assert!(!profile.capabilities.consistency_proofs);
    }

    #[test]
    fn an_absolute_profile_path_is_left_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let text = format!(
            "{}\n[policy.adaptor_profiles.p]\nhash = \"{GENESIS}\"\npath = \"/etc/profile.md\"\n",
            minimal()
        );
        let path = write_policy(dir.path(), &text);
        let loaded = load(&path).expect("valid policy");
        assert_eq!(loaded.profiles["p"].path, PathBuf::from("/etc/profile.md"));
    }

    #[test]
    fn an_inline_dataset_key_is_decoded_and_length_checked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let text = format!(
            "{}\n[policy.dataset_keys.customers]\nhex = \"{}\"\n",
            minimal(),
            "05".repeat(32)
        );
        let path = write_policy(dir.path(), &text);
        let loaded = load(&path).expect("valid policy");
        assert_eq!(loaded.trust.dataset_keys["customers"], vec![5u8; 32]);

        let text = format!("{}\n[policy.dataset_keys.customers]\nhex = \"0505\"\n", minimal());
        let path = write_policy(dir.path(), &text);
        let error = load(&path).expect_err("short key");
        assert!(error.to_string().contains("expected 32"), "{error}");
    }

    #[test]
    fn a_dataset_key_file_is_opened_under_the_secret_rules() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("customers.key");
        std::fs::write(&key_path, format!("{}\n", "05".repeat(32))).expect("write key");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only");
        let text =
            format!("{}\n[policy.dataset_keys.customers]\nfile = \"customers.key\"\n", minimal());
        let path = write_policy(dir.path(), &text);
        let loaded = load(&path).expect("valid policy");
        assert_eq!(loaded.trust.dataset_keys["customers"], vec![5u8; 32]);

        // Relaxing the key file's mode is enough to make the same policy unusable.
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))
            .expect("relax mode");
        assert!(load(&path).is_err());
    }

    #[test]
    fn a_dataset_key_naming_both_or_neither_source_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let both = format!(
            "{}\n[policy.dataset_keys.c]\nfile = \"a\"\nhex = \"{}\"\n",
            minimal(),
            "05".repeat(32)
        );
        assert!(load(&write_policy(dir.path(), &both)).is_err());
        let neither = format!("{}\n[policy.dataset_keys.c]\n", minimal());
        assert!(load(&write_policy(dir.path(), &neither)).is_err());
    }

    #[test]
    fn a_non_hex_dataset_key_never_echoes_the_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let text = format!("{}\n[policy.dataset_keys.c]\nhex = \"zzsecretzz\"\n", minimal());
        let error = load(&write_policy(dir.path(), &text)).expect_err("non-hex");
        assert!(!error.to_string().contains("zzsecretzz"), "secret echoed: {error}");
    }

    #[test]
    fn endpoints_are_addresses_and_are_scheme_checked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let text = format!(
            "{}\n[endpoints]\nmirror = \"https://mirror.example\"\n\
             witness = \"http://127.0.0.1:8080\"\n",
            minimal()
        );
        let loaded = load(&write_policy(dir.path(), &text)).expect("valid policy");
        assert_eq!(loaded.endpoints.mirror.as_deref(), Some("https://mirror.example"));

        let text = format!("{}\n[endpoints]\nmirror = \"ftp://mirror.example\"\n", minimal());
        assert!(load(&write_policy(dir.path(), &text)).is_err());
    }

    #[test]
    fn limits_override_only_what_they_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let text = format!(
            "{}\n[policy.limits]\nmax_work_units = 7\n\
             [limits.network]\nmax_entries = 11\n[limits.local]\nmax_corpus_entries = 13\n",
            minimal()
        );
        let loaded = load(&write_policy(dir.path(), &text)).expect("valid policy");
        assert_eq!(loaded.trust.limits.max_work_units, 7);
        assert_eq!(loaded.trust.limits.max_depth, Limits::default().max_depth);
        assert_eq!(loaded.network.max_entries, 11);
        assert_eq!(loaded.network.max_total_bytes, NetworkLimits::default().max_total_bytes);
        assert_eq!(loaded.local.max_corpus_entries, 13);
    }

    #[test]
    fn dataset_key_bytes_are_wiped_when_the_policy_is_dropped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let text = format!(
            "{}\n[policy.dataset_keys.customers]\nhex = \"{}\"\n",
            minimal(),
            "05".repeat(32)
        );
        let mut loaded = load(&write_policy(dir.path(), &text)).expect("valid policy");
        // The destructor runs exactly this on every held key: `Zeroize for Vec<u8>` wipes the
        // whole allocated buffer and then truncates, so an emptied vector is the observable
        // result of a wiped one.
        let key = loaded.trust.dataset_keys.get_mut("customers").expect("held");
        assert_eq!(key.as_slice(), [5u8; 32]);
        key.zeroize();
        assert!(key.is_empty(), "dataset key bytes must not survive the wipe");
    }

    #[test]
    fn a_policy_that_is_not_utf8_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, [0xff, 0xfe, 0x00]).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
        assert!(load(&path).is_err());
    }
}
