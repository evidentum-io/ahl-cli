//! Locating the `ahl-core` conformance corpus, for test and fuzz code only.
//!
//! The corpus is `test_data/` inside `ahl-core`, and `ahl-core` is a registry dependency: there
//! is no sibling working tree to read it from, and there must not be one, because an outside
//! contributor holds only what `cargo` resolved for them. The directory is therefore found
//! through the **resolved dependency** rather than through a relative path:
//!
//! 1. `AHL_CORE_TEST_DATA`, when set, names the directory outright. This is the escape hatch for
//!    an environment where `cargo` is not on `PATH` — a fuzzing host, a sandbox — and for
//!    developing against an unpublished corpus.
//! 2. Otherwise `cargo metadata` is asked about this crate's own manifest, the package named
//!    `ahl-core` is taken from the resolved graph, and the corpus is `test_data/` beside its
//!    manifest. For a registry dependency that is the unpacked source under `CARGO_HOME`; in a
//!    workspace where `ahl-core` is patched to a path, it is that path. Both are correct without
//!    the caller knowing which applies.
//!
//! `ahl-core` ships `test_data/` inside its `.crate`, so strategy 2 holds for the published
//! release. `cargo metadata` may need the network on a cold cache, exactly as the build that
//! precedes it does.
//!
//! This module is compiled into test and fuzz code only, never into the library or a binary:
//! nothing shipped spawns `cargo`. It is shared, rather than copied, by `#[path]` from
//! `tests/common/mod.rs` and from the fuzz crate's own `lib.rs`.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The package whose `test_data/` directory is the conformance corpus.
const PACKAGE: &str = "ahl-core";

/// The variable that names the corpus directory outright.
const OVERRIDE: &str = "AHL_CORE_TEST_DATA";

/// The conformance corpus directory, or why neither strategy produced one.
///
/// Never panics: the fuzz crate calls this under a no-panic lint policy of its own.
///
/// # Errors
///
/// Where `AHL_CORE_TEST_DATA` names something that is not a directory, where `cargo metadata`
/// cannot be run or fails, where its output names no `ahl-core`, or where the directory it
/// points at does not exist. The message names both strategies, so a reader is never left
/// guessing which one to fix.
pub fn locate() -> Result<PathBuf, String> {
    if let Some(explicit) = std::env::var_os(OVERRIDE) {
        let path = PathBuf::from(explicit);
        return if path.is_dir() {
            Ok(path)
        } else {
            Err(format!("`{OVERRIDE}` is set to `{}`, which is not a directory", path.display()))
        };
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let root = from_metadata(&manifest)?;
    let corpus = root.join("test_data");
    if corpus.is_dir() {
        Ok(corpus)
    } else {
        Err(unavailable(&format!(
            "`{PACKAGE}` resolved to `{}`, which has no `test_data/` directory",
            root.display()
        )))
    }
}

/// The directory holding the resolved `ahl-core`'s manifest.
fn from_metadata(manifest: &Path) -> Result<PathBuf, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(&cargo)
        .args(["metadata", "--format-version", "1", "--manifest-path"])
        .arg(manifest)
        .output()
        .map_err(|source| {
            unavailable(&format!("`{} metadata` could not be run: {source}", cargo.display()))
        })?;
    if !output.status.success() {
        return Err(unavailable(&format!(
            "`cargo metadata --manifest-path {}` failed: {}",
            manifest.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|source| unavailable(&format!("`cargo metadata` did not emit JSON: {source}")))?;
    let packages = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| unavailable("`cargo metadata` emitted no `packages` array"))?;
    let mut found: Vec<(&str, &str)> = packages
        .iter()
        .filter(|package| package.get("name").and_then(serde_json::Value::as_str) == Some(PACKAGE))
        .filter_map(|package| {
            let version = package.get("version").and_then(serde_json::Value::as_str)?;
            let path = package.get("manifest_path").and_then(serde_json::Value::as_str)?;
            Some((version, path))
        })
        .collect();
    found.sort_unstable();
    found.dedup();
    // Exactly one resolved `ahl-core` is the only case that can be answered without guessing.
    // Two would mean the graph carries two versions of the corpus, and picking either would
    // silently test against material this crate does not depend on.
    match found.split_first() {
        Some((&(_, path), [])) => Path::new(path)
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| unavailable(&format!("`{path}` has no parent directory"))),
        Some(_) => Err(unavailable(&format!(
            "`cargo metadata` resolved {} versions of `{PACKAGE}` ({}); set `{OVERRIDE}` to say \
             which corpus to test against",
            found.len(),
            found.iter().map(|&(version, _)| version).collect::<Vec<_>>().join(", ")
        ))),
        None => Err(unavailable(&format!(
            "`cargo metadata --manifest-path {}` resolved no package named `{PACKAGE}`",
            manifest.display()
        ))),
    }
}

/// One message, naming both strategies, whichever of them failed.
fn unavailable(detail: &str) -> String {
    format!(
        "the `{PACKAGE}` conformance corpus is unavailable: {detail}. It is located either from \
         `{OVERRIDE}`, which names the directory outright, or from the `{PACKAGE}` package \
         `cargo metadata` resolves for this crate, whose `test_data/` directory is the corpus."
    )
}

/// The conformance corpus directory.
///
/// # Panics
///
/// Where [`locate`] reports the corpus is unavailable. A test that cannot read the corpus it
/// asserts against has no verdict to give, and reporting that as a failure is the point.
#[cfg(test)]
pub fn corpus_dir() -> PathBuf {
    use std::sync::OnceLock;

    static DIR: OnceLock<PathBuf> = OnceLock::new();
    // Resolved once per test process: `cargo metadata` is a subprocess, and hundreds of tests
    // read the corpus.
    DIR.get_or_init(|| match locate() {
        Ok(path) => path,
        Err(reason) => panic!("{reason}"),
    })
    .clone()
}
