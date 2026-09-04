//! Secure open, not stat-then-open.
//!
//! A `stat` followed by an `open` checks one file and reads another: between the two calls a
//! hostile filesystem can swap the path for a symlink to something else. Every check here is
//! therefore made on the **open handle** — never on the pathname — and the final path
//! component is opened with `O_NOFOLLOW` so a symlink is refused outright rather than
//! silently traversed.
//!
//! Two strengths, because two kinds of input:
//!
//! * [`read_regular`] — for artifacts (receipts, corpora, adaptor profiles). The handle must
//!   be a regular file. Nothing is assumed about its permissions: an artifact is untrusted
//!   input whose integrity comes from its own content, not from its mode bits.
//! * [`read_secret`] — for the trust policy, signing keys and dataset-key sources. The handle
//!   must additionally be owner-only (`0o600`-style: no group or other bits at all) and owned
//!   by the effective uid. The attack this closes is a hostile filesystem swapping a policy
//!   for one anchored to an attacker corpus.
//!
//! Both are bounded: a read stops at the caller's byte cap and reports exhaustion rather than
//! filling memory, so a hostile file cannot exhaust memory where a hostile server cannot.

use std::fs::File;
use std::io::Read as _;
use std::path::Path;

use rustix::fs::{FileType, Mode, OFlags};

use crate::error::{CliError, CliResult};

/// How strictly the handle is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Strength {
    /// Regular file. Nothing assumed about permissions.
    Artifact,
    /// Regular file, owner-only mode, owned by the effective uid.
    Secret,
}

fn open_checked(what: &'static str, path: &Path, strength: Strength) -> CliResult<File> {
    let fail = |detail: String| CliError::Open { what, path: path.display().to_string(), detail };

    // `NOFOLLOW` applies to the final component only; that is exactly where the swap this
    // guards against happens, and is what every platform this crate targets supports.
    let fd =
        rustix::fs::open(path, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())
            .map_err(|errno| {
                if errno == rustix::io::Errno::LOOP || errno == rustix::io::Errno::MLINK {
                    fail("final path component is a symbolic link".to_owned())
                } else {
                    fail(errno.to_string())
                }
            })?;

    let stat = rustix::fs::fstat(&fd).map_err(|errno| fail(errno.to_string()))?;

    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(fail("not a regular file".to_owned()));
    }

    if strength == Strength::Secret {
        let permissions = stat.st_mode & 0o777;
        if permissions & 0o077 != 0 {
            return Err(fail(format!(
                "mode {permissions:04o} grants access beyond the owner; \
                 secrets and trust policy must be owner-only"
            )));
        }
        let euid = rustix::process::geteuid().as_raw();
        if stat.st_uid != euid {
            return Err(fail(format!(
                "owned by uid {} but the effective uid is {euid}",
                stat.st_uid
            )));
        }
    }

    Ok(File::from(fd))
}

fn read_bounded(
    what: &'static str,
    path: &Path,
    file: &mut File,
    cap: usize,
) -> CliResult<Vec<u8>> {
    let mut buffer = Vec::new();
    // `cap + 1` so an exactly-`cap`-byte file is accepted and a `cap + 1`-byte one is not.
    // `cap` reaches here from the policy file, so the increment saturates rather than wrapping
    // a `usize::MAX` budget round to a one-byte one.
    let limit = (cap as u64).saturating_add(1);
    let read = file.take(limit).read_to_end(&mut buffer).map_err(|source| CliError::Open {
        what,
        path: path.display().to_string(),
        detail: source.to_string(),
    })?;
    if read > cap {
        return Err(CliError::LimitExhausted(format!(
            "{what} at `{}` exceeds the {cap}-byte budget for local files",
            path.display()
        )));
    }
    Ok(buffer)
}

/// Read an artifact: regular file, no symlinked final component, bounded by `cap` bytes.
///
/// # Errors
///
/// [`CliError::Open`] if the handle checks fail, [`CliError::LimitExhausted`] if the file is
/// larger than `cap`.
pub fn read_regular(what: &'static str, path: &Path, cap: usize) -> CliResult<Vec<u8>> {
    let mut file = open_checked(what, path, Strength::Artifact)?;
    read_bounded(what, path, &mut file, cap)
}

/// Read a secret: regular file, owner-only, owned by the effective uid, bounded by `cap`.
///
/// # Errors
///
/// [`CliError::Open`] if any handle check fails, [`CliError::LimitExhausted`] if the file is
/// larger than `cap`.
pub fn read_secret(what: &'static str, path: &Path, cap: usize) -> CliResult<Vec<u8>> {
    let mut file = open_checked(what, path, Strength::Secret)?;
    read_bounded(what, path, &mut file, cap)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn write(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut file = File::create(&path).expect("create test file");
        file.write_all(bytes).expect("write test file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .expect("set test mode");
        path
    }

    #[test]
    fn an_owner_only_regular_file_is_accepted_as_a_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(dir.path(), "key", b"00ff", 0o600);
        assert_eq!(read_secret("key", &path, 64).expect("readable"), b"00ff");
    }

    #[test]
    fn a_group_readable_secret_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(dir.path(), "key", b"00ff", 0o640);
        let error = read_secret("key", &path, 64).expect_err("group-readable");
        assert!(error.to_string().contains("owner-only"), "{error}");
    }

    #[test]
    fn a_world_readable_secret_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(dir.path(), "key", b"00ff", 0o604);
        assert!(read_secret("key", &path, 64).is_err());
    }

    #[test]
    fn a_world_readable_artifact_is_accepted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(dir.path(), "receipt.ahl", b"{}", 0o644);
        assert_eq!(read_regular("receipt", &path, 64).expect("readable"), b"{}");
    }

    #[test]
    fn a_symlinked_final_component_is_refused_rather_than_traversed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = write(dir.path(), "real", b"secret", 0o600);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let error = read_secret("key", &link, 64).expect_err("symlink refused");
        assert!(error.to_string().contains("symbolic link"), "{error}");
    }

    #[test]
    fn a_directory_is_not_a_regular_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = read_regular("receipt", dir.path(), 64).expect_err("directory refused");
        assert!(error.to_string().contains("not a regular file"), "{error}");
    }

    #[test]
    fn an_absent_file_is_an_open_failure_not_a_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(read_regular("receipt", &dir.path().join("nope"), 64).is_err());
    }

    #[test]
    fn a_file_at_exactly_the_cap_is_read_and_one_byte_more_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(dir.path(), "a", &[b'x'; 16], 0o644);
        assert_eq!(read_regular("receipt", &path, 16).expect("at cap").len(), 16);
        let error = read_regular("receipt", &path, 15).expect_err("over cap");
        assert!(error.to_string().contains("budget"), "{error}");
    }
}
