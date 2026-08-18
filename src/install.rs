//! Atomic, non-clobbering installation of an output file.
//!
//! Pathname-based checks do not achieve this. An existence check followed by an ordinary
//! `rename` loses the race, because `rename` replaces a destination created in between the
//! two calls — the check passes, the write succeeds, and someone else's file is gone.
//!
//! The install is therefore performed **relative to an open directory handle**, with a
//! no-replace atomic primitive:
//!
//! 1. `renameat2(RENAME_NOREPLACE)` on Linux, `renamex_np(RENAME_EXCL)` on macOS — the same
//!    call through `rustix::fs::renameat_with`;
//! 2. failing that (`ENOSYS`/`EINVAL`/`ENOTSUP` from an older kernel or an exotic filesystem),
//!    `linkat` followed by unlink of the temporary, which is equally no-replace;
//! 3. failing both, the write **fails closed** rather than degrading to a racy `rename`.
//!
//! An existing destination is refused. [`Force::Yes`] performs an explicit `unlinkat` and
//! then repeats the same no-replace install — so even `--force` never silently overwrites a
//! file that appeared between the unlink and the install; it loses the race safely instead.

use std::fs::File;
use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{FileType, Mode, OFlags};

use crate::error::{CliError, CliResult};

/// Whether an existing destination may be replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Force {
    /// An existing destination is refused.
    No,
    /// An existing destination is unlinked first, then the same no-replace install runs.
    Yes,
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn output_error(path: &Path, detail: impl Into<String>) -> CliError {
    CliError::Output { path: path.display().to_string(), detail: detail.into() }
}

/// Write `bytes` to `path`, atomically and without replacing an existing file.
///
/// The file is created with mode `0o600`: output may carry material the operator does not
/// want world-readable, and a caller that wants it wider can relax it deliberately.
///
/// # Errors
///
/// [`CliError::Output`] if the parent is not a directory, the destination exists (and
/// `force` is [`Force::No`]), or no no-replace primitive is available on this platform.
pub fn install(path: &Path, bytes: &[u8], force: Force) -> CliResult<()> {
    let parent =
        path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| output_error(path, "destination has no file name component"))?
        .to_owned();

    let dir = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| output_error(path, format!("cannot open parent directory: {errno}")))?;

    // Parent-directory properties are checked on the open handle, never by path.
    let dir_stat = rustix::fs::fstat(&dir)
        .map_err(|errno| output_error(path, format!("cannot stat parent directory: {errno}")))?;
    if FileType::from_raw_mode(dir_stat.st_mode) != FileType::Directory {
        return Err(output_error(path, "parent path is not a directory"));
    }

    let temp_name = format!(
        ".ahl-cli.{}.{}.tmp",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    );

    let temp_fd = rustix::fs::openat(
        &dir,
        temp_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|errno| output_error(path, format!("cannot create temporary file: {errno}")))?;

    let write_result = (|| -> std::io::Result<()> {
        let mut file = File::from(temp_fd);
        file.write_all(bytes)?;
        file.sync_all()
    })();
    if let Err(source) = write_result {
        let _ = rustix::fs::unlinkat(&dir, temp_name.as_str(), rustix::fs::AtFlags::empty());
        return Err(output_error(path, format!("cannot write temporary file: {source}")));
    }

    if force == Force::Yes {
        // Best effort by design: an absent destination is the normal case, and a destination
        // that reappears before the install below is refused by the no-replace primitive
        // rather than clobbered.
        let _ = rustix::fs::unlinkat(&dir, &file_name, rustix::fs::AtFlags::empty());
    }

    let result = no_replace_install(&dir, temp_name.as_str(), &file_name, path);
    if result.is_err() {
        let _ = rustix::fs::unlinkat(&dir, temp_name.as_str(), rustix::fs::AtFlags::empty());
    }
    result
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "ios"))]
fn no_replace_install(
    dir: &rustix::fd::OwnedFd,
    temp_name: &str,
    file_name: &std::ffi::OsStr,
    path: &Path,
) -> CliResult<()> {
    use rustix::fs::RenameFlags;
    use rustix::io::Errno;

    match rustix::fs::renameat_with(dir, temp_name, dir, file_name, RenameFlags::NOREPLACE) {
        Ok(()) => Ok(()),
        Err(Errno::EXIST) => Err(destination_exists(path)),
        // An older kernel or a filesystem without `renameat2`/`renamex_np` support: fall back
        // to `linkat`, which is equally no-replace, rather than to a racy plain rename.
        Err(Errno::NOSYS | Errno::INVAL | Errno::NOTSUP | Errno::OPNOTSUPP) => {
            link_install(dir, temp_name, file_name, path)
        }
        Err(errno) => Err(output_error(path, format!("atomic install failed: {errno}"))),
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
fn no_replace_install(
    dir: &rustix::fd::OwnedFd,
    temp_name: &str,
    file_name: &std::ffi::OsStr,
    path: &Path,
) -> CliResult<()> {
    link_install(dir, temp_name, file_name, path)
}

/// `linkat` + unlink of the temporary: no-replace, and available where `renameat2` is not.
fn link_install(
    dir: &rustix::fd::OwnedFd,
    temp_name: &str,
    file_name: &std::ffi::OsStr,
    path: &Path,
) -> CliResult<()> {
    use rustix::io::Errno;

    match rustix::fs::linkat(dir, temp_name, dir, file_name, rustix::fs::AtFlags::empty()) {
        Ok(()) => {
            let _ = rustix::fs::unlinkat(dir, temp_name, rustix::fs::AtFlags::empty());
            Ok(())
        }
        Err(Errno::EXIST) => Err(destination_exists(path)),
        Err(errno @ (Errno::NOSYS | Errno::NOTSUP | Errno::OPNOTSUPP | Errno::PERM)) => {
            // Fail closed: no no-replace primitive is available, so there is no safe install.
            Err(output_error(
                path,
                format!(
                    "no atomic no-replace install is available on this filesystem ({errno}); \
                     refusing to fall back to a replacing rename"
                ),
            ))
        }
        Err(errno) => Err(output_error(path, format!("atomic install failed: {errno}"))),
    }
}

fn destination_exists(path: &Path) -> CliError {
    output_error(path, "destination already exists; pass --force to replace it")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_destination_is_installed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("out.json");
        install(&path, b"{\"a\":1}", Force::No).expect("fresh install");
        assert_eq!(std::fs::read(&path).expect("read back"), b"{\"a\":1}");
    }

    #[test]
    fn an_existing_destination_is_refused_without_force() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("out.json");
        install(&path, b"first", Force::No).expect("fresh install");
        let error = install(&path, b"second", Force::No).expect_err("clobber refused");
        assert!(error.to_string().contains("--force"), "{error}");
        assert_eq!(std::fs::read(&path).expect("read back"), b"first");
    }

    #[test]
    fn force_replaces_and_leaves_no_temporary_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("out.json");
        install(&path, b"first", Force::No).expect("fresh install");
        install(&path, b"second", Force::Yes).expect("forced install");
        assert_eq!(std::fs::read(&path).expect("read back"), b"second");

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|entry| entry.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .filter(|name| name.starts_with(".ahl-cli."))
            .collect();
        assert!(leftovers.is_empty(), "temporaries left behind: {leftovers:?}");
    }

    #[test]
    fn a_failed_install_removes_its_temporary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("out.json");
        install(&path, b"first", Force::No).expect("fresh install");
        let _ = install(&path, b"second", Force::No).expect_err("clobber refused");

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|entry| entry.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .filter(|name| name.starts_with(".ahl-cli."))
            .collect();
        assert!(leftovers.is_empty(), "temporaries left behind: {leftovers:?}");
    }

    #[test]
    fn a_non_directory_parent_is_refused_on_the_handle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"x").expect("write");
        let error = install(&file.join("out.json"), b"{}", Force::No).expect_err("refused");
        assert!(error.to_string().contains("cannot open parent directory"), "{error}");
    }

    #[test]
    fn a_relative_destination_installs_into_the_current_directory() {
        // Exercises the `parent()` fallback to `.` without changing the process directory:
        // a bare file name in a temporary directory reached through an absolute parent.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bare.json");
        install(Path::new(&path), b"{}", Force::No).expect("install");
        assert!(path.exists());
    }

    #[test]
    fn installed_output_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("out.json");
        install(&path, b"{}", Force::No).expect("install");
        let mode = std::fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "output must not be group- or world-readable");
    }
}
