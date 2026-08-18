//! Signing-key handling for `emit`.
//!
//! Rules, all of them load-bearing:
//!
//! * Key material is read from a **file** (`--key-file`) or a **named environment variable**
//!   (`--key-env`). Never from a command-line argument — `argv` is world-readable in `ps`.
//! * One encoding: a single line of hex encoding a 32-byte Ed25519 seed, trailing newline
//!   optional. No PKCS#8, no PEM, no key files with headers, in v0.1.
//! * A key file is opened under the §4 secret rules (regular file, owner-only, owned by the
//!   effective uid, symlinked final component refused).
//! * Secret bytes are never logged, never in JSON output, never in an error message, and are
//!   zeroized after use. Every error in this module is written so it cannot echo the input.
//! * `key_id` is derived per adaptor profile §7.2 and printed, so the operator can confirm
//!   which key signed.
//!
//! `verify` and `inspect` never construct a [`SigningMaterial`]: no verification command has a
//! code path that opens signing material at all.

use std::path::Path;

use ahl_core::TestKey;
use zeroize::Zeroize as _;

use crate::error::{CliError, CliResult};
use crate::secure;

/// Byte cap on a key file: 64 hex digits plus generous whitespace.
const KEY_FILE_CAP: usize = 512;

/// Where the private signing seed comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// A file holding one line of hex.
    File(std::path::PathBuf),
    /// The name of an environment variable holding one line of hex.
    Env(String),
}

/// A loaded Ed25519 signing key.
///
/// The seed is consumed at construction and never retained: `ahl_core::TestKey` keeps the
/// expanded signing key, and this type exposes only the public identity plus a signing
/// operation.
pub struct SigningMaterial {
    key: TestKey,
}

impl std::fmt::Debug for SigningMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render key material, not even accidentally through a derived `Debug`.
        f.debug_struct("SigningMaterial").field("key_id", &self.key.key_id()).finish()
    }
}

impl SigningMaterial {
    /// Load a signing key from `source`.
    ///
    /// # Errors
    ///
    /// [`CliError::Open`] if a key file fails the §4 handle checks; [`CliError::Usage`] if the
    /// named environment variable is unset; [`CliError::Malformed`] if the contents are not a
    /// single line of hex encoding exactly 32 bytes. No error echoes the material.
    pub fn load(source: &KeySource) -> CliResult<Self> {
        let mut text = match source {
            KeySource::File(path) => Self::read_file(path)?,
            KeySource::Env(name) => Self::read_env(name)?,
        };
        let result = Self::from_hex(text.trim());
        text.zeroize();
        result
    }

    fn read_file(path: &Path) -> CliResult<String> {
        let mut bytes = secure::read_secret("signing key", path, KEY_FILE_CAP)?;
        let text = String::from_utf8(bytes.clone());
        bytes.zeroize();
        text.map_err(|_| CliError::Malformed {
            what: "signing key",
            detail: "key file is not valid UTF-8".to_owned(),
        })
    }

    fn read_env(name: &str) -> CliResult<String> {
        std::env::var(name).map_err(|_| {
            CliError::Usage(format!("environment variable `{name}` is not set or is not UTF-8"))
        })
    }

    fn from_hex(hex_text: &str) -> CliResult<Self> {
        let malformed = |detail: &str| CliError::Malformed {
            what: "signing key",
            detail: detail.to_owned(),
        };
        if hex_text.lines().count() > 1 {
            return Err(malformed(
                "key material must be a single line of hex; no PKCS#8, no PEM, no headers",
            ));
        }
        if hex_text.len() != 64 {
            return Err(malformed(
                "key material must be exactly 64 hex digits encoding a 32-byte Ed25519 seed",
            ));
        }
        let key = TestKey::from_seed_hex("signing key", hex_text)
            .map_err(|_| malformed("key material is not 64 hex digits"))?;
        Ok(Self { key })
    }

    /// The `key_id` this key signs under, as `sha256:<hex>` (adaptor profile §7.2).
    #[must_use]
    pub fn key_id(&self) -> String {
        self.key.key_id()
    }

    /// The public key as `base64:<raw 32 bytes>`.
    #[must_use]
    pub fn pubkey(&self) -> String {
        self.key.pubkey()
    }

    /// Build a signed envelope over `payload` (core spec §2.1).
    #[must_use]
    pub fn envelope(&self, payload: serde_json::Value) -> serde_json::Value {
        ahl_core::envelope(payload, &self.key)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    const SEED: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    fn key_file(dir: &Path, contents: &str, mode: u32) -> std::path::PathBuf {
        let path = dir.join("k.seed");
        std::fs::write(&path, contents).expect("write key");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("mode");
        path
    }

    #[test]
    fn a_hex_seed_with_or_without_a_trailing_newline_loads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bare = SigningMaterial::load(&KeySource::File(key_file(dir.path(), SEED, 0o600)))
            .expect("bare seed");
        let dir2 = tempfile::tempdir().expect("tempdir");
        let newline = SigningMaterial::load(&KeySource::File(key_file(
            dir2.path(),
            &format!("{SEED}\n"),
            0o600,
        )))
        .expect("seed with newline");
        assert_eq!(bare.key_id(), newline.key_id());
        assert!(bare.key_id().starts_with("sha256:"));
        assert!(bare.pubkey().starts_with("base64:"));
    }

    #[test]
    fn a_world_readable_key_file_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = key_file(dir.path(), SEED, 0o644);
        assert!(SigningMaterial::load(&KeySource::File(path)).is_err());
    }

    #[test]
    fn pem_and_pkcs8_are_refused_by_shape() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQ==\n-----END PRIVATE KEY-----\n";
        let path = key_file(dir.path(), pem, 0o600);
        let error = SigningMaterial::load(&KeySource::File(path)).expect_err("PEM refused");
        assert!(error.to_string().contains("single line of hex"), "{error}");
    }

    #[test]
    fn a_wrong_length_or_non_hex_seed_is_refused_without_echoing_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = key_file(dir.path(), "0011", 0o600);
        let error = SigningMaterial::load(&KeySource::File(path)).expect_err("short seed");
        assert!(!error.to_string().contains("0011"), "material echoed: {error}");

        let dir = tempfile::tempdir().expect("tempdir");
        let path = key_file(dir.path(), &"zz".repeat(32), 0o600);
        let error = SigningMaterial::load(&KeySource::File(path)).expect_err("non-hex seed");
        assert!(!error.to_string().contains("zz"), "material echoed: {error}");
    }

    #[test]
    fn an_unset_environment_variable_is_a_usage_error() {
        let error = SigningMaterial::load(&KeySource::Env(
            "AHL_CLI_TEST_KEY_THAT_IS_NEVER_SET".to_owned(),
        ))
        .expect_err("unset");
        assert!(matches!(error, CliError::Usage(_)), "{error}");
    }

    #[test]
    fn the_debug_rendering_never_carries_key_material() {
        let dir = tempfile::tempdir().expect("tempdir");
        let material = SigningMaterial::load(&KeySource::File(key_file(dir.path(), SEED, 0o600)))
            .expect("seed");
        let rendered = format!("{material:?}");
        assert!(rendered.contains("key_id"));
        assert!(!rendered.contains(SEED), "seed echoed in Debug: {rendered}");
    }

    #[test]
    fn an_envelope_is_signed_over_the_canonical_payload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let material = SigningMaterial::load(&KeySource::File(key_file(dir.path(), SEED, 0o600)))
            .expect("seed");
        let envelope = material.envelope(serde_json::json!({ "type": "ingestion" }));
        let key_id = material.key_id();
        let pubkey = material.pubkey();
        assert!(
            ahl_core::verify_envelope(&envelope, |id| (id == key_id).then(|| pubkey.clone()))
                .expect("well-formed envelope")
        );
    }

    #[test]
    fn a_key_file_that_is_not_utf8_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("k.seed");
        std::fs::write(&path, [0xffu8, 0xfe]).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
        assert!(SigningMaterial::load(&KeySource::File(path)).is_err());
    }
}
