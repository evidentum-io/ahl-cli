//! Handle-relative directory operations, and the no-replace atomic install.
//!
//! Pathname-based checks do not achieve atomicity. An existence check followed by an ordinary
//! `rename` loses the race, because `rename` replaces a destination created in between the two
//! calls — the check passes, the write succeeds, and someone else's file is gone. Worse, a
//! predictable temporary pathname in a directory an attacker can write to is a redirect: plant
//! a symlink there and the write lands wherever the symlink points.
//!
//! Everything here is therefore performed **relative to an open directory handle**
//! ([`Dir`]), never by path:
//!
//! * the directory itself is opened with `O_NOFOLLOW`, and its type is checked on the *handle*;
//! * temporaries are created with `openat(O_CREAT | O_EXCL | O_NOFOLLOW)` under an
//!   **unpredictable** name — `O_EXCL` is what defeats a planted symlink, and the
//!   unpredictability is defence in depth against an attacker pre-planting the name at all;
//! * the install is a no-replace atomic operation: `renameat2(RENAME_NOREPLACE)` on Linux,
//!   `renamex_np(RENAME_EXCL)` on macOS, or `linkat` plus unlink of the temporary;
//! * where no such primitive exists the write **fails closed** rather than degrading to a racy
//!   `rename`.
//!
//! [`Force::Yes`] and [`Dir::replace`] perform an explicit `unlinkat` and then repeat the same
//! no-replace install, so even a deliberate replacement never silently overwrites a file that
//! appeared in between; it loses the race safely instead.
//!
//! This module is used by `emit`'s output **and by the cache**. A cache entry has no
//! evidentiary weight, but "no evidentiary weight" was never a licence to write outside the
//! directory the operator named.

use std::collections::hash_map::RandomState;
use std::ffi::OsStr;
use std::fs::File;
use std::hash::{BuildHasher as _, Hasher as _};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{AtFlags, FileType, Mode, OFlags};

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

/// An unpredictable temporary name.
///
/// Correctness comes from `O_EXCL`: a planted file or symlink at this name makes the create
/// fail rather than redirect. Unpredictability is the second layer — without it an attacker
/// who can write to the directory can pre-plant every name the process will use and stall it
/// indefinitely. `RandomState` is seeded by the OS once per process, which is the property
/// wanted here; no cryptographic strength is claimed or needed.
fn temp_name() -> String {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(counter);
    hasher.write_u32(std::process::id());
    format!(".ahl-cli.{:016x}.tmp", hasher.finish())
}

fn output_error(path: &Path, detail: impl Into<String>) -> CliError {
    CliError::Output { path: path.display().to_string(), detail: detail.into() }
}

/// An open directory handle. Every mutation below is relative to it.
#[derive(Debug)]
pub struct Dir {
    fd: rustix::fd::OwnedFd,
    /// Retained for error messages and for enumeration, which only drives cache eviction.
    path: PathBuf,
}

impl Dir {
    /// Open an existing directory and check its type on the handle.
    ///
    /// # Errors
    ///
    /// [`CliError::Output`] if it cannot be opened or is not a directory.
    pub fn open(path: &Path) -> CliResult<Self> {
        let fd = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| output_error(path, format!("cannot open directory: {errno}")))?;

        // Checked on the handle, never by path.
        let stat = rustix::fs::fstat(&fd)
            .map_err(|errno| output_error(path, format!("cannot stat directory: {errno}")))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            return Err(output_error(path, "path is not a directory"));
        }
        Ok(Self { fd, path: path.to_path_buf() })
    }

    /// Create the directory (and its parents) if needed, and return a handle to it, resolving
    /// each component **once**, relative to the handle of its parent.
    ///
    /// Creating by path and then opening by path is two independent resolutions of the same
    /// name, and the gap between them is a race: whatever the second resolution lands on need
    /// not be what the first one made. `create_dir_all` followed by an `open` therefore hands
    /// back a handle to a directory nobody checked was the one just created — and every
    /// handle-relative guarantee the rest of this module provides is anchored on that handle.
    ///
    /// So the walk is handle-relative from the start: `mkdirat` under the parent handle (an
    /// existing entry is the normal case and not an error), then `openat` under the same
    /// handle, and the type of what was opened is checked on the resulting descriptor. Each
    /// name is resolved exactly once, against a directory this process already holds open, so
    /// no component of the path can be swapped for a different one between the two calls.
    ///
    /// The **final** component is opened `O_NOFOLLOW`, matching [`Self::open`]: the directory
    /// every subsequent write lands in is never reached through a symlink. Intermediate
    /// components are followed, because they routinely are symlinks on healthy systems — a
    /// platform temporary directory commonly sits behind one — and refusing them would fail
    /// closed on ordinary configurations rather than on hostile ones.
    ///
    /// Directories are created owner-only, on the same reasoning as the `0600` temporaries
    /// below: nothing here is written for another user to read.
    ///
    /// # Errors
    ///
    /// [`CliError::Output`] if any component cannot be created or opened, or if what was
    /// opened is not a directory.
    pub fn create(path: &Path) -> CliResult<Self> {
        use std::path::Component;

        let anchor = if path.is_absolute() { "/" } else { "." };
        let mut fd = rustix::fs::openat(
            rustix::fs::CWD,
            anchor,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| output_error(path, format!("cannot open `{anchor}`: {errno}")))?;

        let mut components = path.components().peekable();
        while let Some(component) = components.next() {
            let name: &OsStr = match component {
                // Already consumed by the anchor above, or a no-op step.
                Component::Prefix(_) | Component::RootDir | Component::CurDir => continue,
                Component::ParentDir => OsStr::new(".."),
                Component::Normal(name) => name,
            };
            let last = components.peek().is_none();

            match rustix::fs::mkdirat(&fd, name, Mode::RWXU) {
                // An existing directory is the ordinary case, not a failure.
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(errno) => {
                    return Err(output_error(
                        path,
                        format!("cannot create `{}`: {errno}", name.to_string_lossy()),
                    ))
                }
            }

            let mut flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
            if last {
                flags |= OFlags::NOFOLLOW;
            }
            fd = rustix::fs::openat(&fd, name, flags, Mode::empty()).map_err(|errno| {
                output_error(path, format!("cannot open `{}`: {errno}", name.to_string_lossy()))
            })?;
        }

        // Checked on the handle, never by path — the same rule as `open`.
        let stat = rustix::fs::fstat(&fd)
            .map_err(|errno| output_error(path, format!("cannot stat directory: {errno}")))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            return Err(output_error(path, "path is not a directory"));
        }
        Ok(Self { fd, path: path.to_path_buf() })
    }

    /// The path this handle was opened from, for messages.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn child(&self, name: &OsStr) -> PathBuf {
        self.path.join(name)
    }

    /// Write `bytes` into a fresh temporary and install it at `name`, atomically and without
    /// replacing an existing entry.
    ///
    /// # Errors
    ///
    /// [`CliError::Output`] if the temporary cannot be created or written, the destination
    /// exists under [`Force::No`], or no no-replace primitive is available.
    pub fn install(&self, name: &OsStr, bytes: &[u8], force: Force) -> CliResult<()> {
        let destination = self.child(name);
        let temp = temp_name();

        // `O_EXCL | O_NOFOLLOW` under the directory handle: a planted file or symlink at this
        // name makes the create fail rather than redirect the write elsewhere.
        let temp_fd = rustix::fs::openat(
            &self.fd,
            temp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|errno| {
            output_error(&destination, format!("cannot create temporary file: {errno}"))
        })?;

        let written = (|| -> std::io::Result<()> {
            let mut file = File::from(temp_fd);
            file.write_all(bytes)?;
            file.sync_all()
        })();
        if let Err(source) = written {
            let _ = rustix::fs::unlinkat(&self.fd, temp.as_str(), AtFlags::empty());
            return Err(output_error(
                &destination,
                format!("cannot write temporary file: {source}"),
            ));
        }

        if force == Force::Yes {
            // Best effort by design: an absent destination is the normal case, and a
            // destination that reappears before the install below is refused by the no-replace
            // primitive rather than clobbered.
            let _ = rustix::fs::unlinkat(&self.fd, name, AtFlags::empty());
        }

        let result = self.no_replace(temp.as_str(), name, &destination);
        if result.is_err() {
            let _ = rustix::fs::unlinkat(&self.fd, temp.as_str(), AtFlags::empty());
        }
        result
    }

    /// Install at `name`, replacing an existing entry.
    ///
    /// Used where replacement is the normal case — a cache index entry pointing at a newer
    /// object. Still handle-relative, still `O_EXCL` on the temporary, and still a no-replace
    /// install after an explicit unlink: a racy plain `rename` is never used.
    ///
    /// # Errors
    ///
    /// As [`Self::install`].
    pub fn replace(&self, name: &OsStr, bytes: &[u8]) -> CliResult<()> {
        self.install(name, bytes, Force::Yes)
    }

    /// Read an entry, refusing to follow a symlink and bounded by `cap` bytes.
    #[must_use]
    pub fn read(&self, name: &OsStr, cap: usize) -> Option<Vec<u8>> {
        let fd = rustix::fs::openat(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .ok()?;
        let stat = rustix::fs::fstat(&fd).ok()?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return None;
        }
        let mut buffer = Vec::new();
        let read = File::from(fd).take(cap as u64 + 1).read_to_end(&mut buffer).ok()?;
        (read <= cap).then_some(buffer)
    }

    /// Remove an entry. An absent entry is not an error.
    pub fn remove(&self, name: &OsStr) {
        let _ = rustix::fs::unlinkat(&self.fd, name, AtFlags::empty());
    }

    /// Enumerate the directory's regular files as `(name, size, last access)`.
    ///
    /// Enumeration is by path rather than by handle because it only ever drives cache
    /// eviction: nothing here decides what is accepted, and every mutation that follows goes
    /// back through the handle. `symlink_metadata` is used so a planted symlink is seen as a
    /// symlink and skipped rather than followed.
    #[must_use]
    pub fn entries(&self) -> Vec<(std::ffi::OsString, u64, std::time::SystemTime)> {
        let Ok(read) = std::fs::read_dir(&self.path) else { return Vec::new() };
        read.filter_map(|entry| {
            let entry = entry.ok()?;
            let metadata = entry.path().symlink_metadata().ok()?;
            if !metadata.is_file() {
                return None;
            }
            let accessed = metadata.accessed().or_else(|_| metadata.modified()).ok()?;
            Some((entry.file_name(), metadata.len(), accessed))
        })
        .collect()
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "ios"))]
    fn no_replace(&self, temp: &str, name: &OsStr, destination: &Path) -> CliResult<()> {
        use rustix::fs::RenameFlags;
        use rustix::io::Errno;

        match rustix::fs::renameat_with(&self.fd, temp, &self.fd, name, RenameFlags::NOREPLACE) {
            Ok(()) => Ok(()),
            Err(Errno::EXIST) => Err(destination_exists(destination)),
            // An older kernel or a filesystem without `renameat2`/`renamex_np`: fall back to
            // `linkat`, which is equally no-replace, never to a racy plain rename.
            Err(Errno::NOSYS | Errno::INVAL | Errno::NOTSUP | Errno::OPNOTSUPP) => {
                self.link_install(temp, name, destination)
            }
            Err(errno) => Err(output_error(destination, format!("atomic install failed: {errno}"))),
        }
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    fn no_replace(&self, temp: &str, name: &OsStr, destination: &Path) -> CliResult<()> {
        self.link_install(temp, name, destination)
    }

    /// `linkat` plus unlink of the temporary: no-replace, and available where `renameat2` is
    /// not.
    fn link_install(&self, temp: &str, name: &OsStr, destination: &Path) -> CliResult<()> {
        use rustix::io::Errno;

        match rustix::fs::linkat(&self.fd, temp, &self.fd, name, AtFlags::empty()) {
            Ok(()) => {
                let _ = rustix::fs::unlinkat(&self.fd, temp, AtFlags::empty());
                Ok(())
            }
            Err(Errno::EXIST) => Err(destination_exists(destination)),
            Err(errno @ (Errno::NOSYS | Errno::NOTSUP | Errno::OPNOTSUPP | Errno::PERM)) => {
                // Fail closed: no no-replace primitive is available, so there is no safe
                // install.
                Err(output_error(
                    destination,
                    format!(
                        "no atomic no-replace install is available on this filesystem \
                         ({errno}); refusing to fall back to a replacing rename"
                    ),
                ))
            }
            Err(errno) => Err(output_error(destination, format!("atomic install failed: {errno}"))),
        }
    }
}

fn destination_exists(path: &Path) -> CliError {
    output_error(path, "destination already exists; pass --force to replace it")
}

/// Write `bytes` to `path`, atomically and without replacing an existing file.
///
/// The file is created with mode `0o600`: output may carry material the operator does not want
/// world-readable, and a caller that wants it wider can relax it deliberately.
///
/// # Errors
///
/// [`CliError::Output`] if the parent is not a directory, the destination exists (and `force`
/// is [`Force::No`]), or no no-replace primitive is available on this platform.
pub fn install(path: &Path, bytes: &[u8], force: Force) -> CliResult<()> {
    let parent =
        path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| output_error(path, "destination has no file name component"))?
        .to_owned();
    let dir = Dir::open(parent)
        .map_err(|source| output_error(path, format!("cannot open parent directory: {source}")))?;
    dir.install(&name, bytes, force)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt as _;

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
        assert!(temporaries(dir.path()).is_empty());
    }

    fn temporaries(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .expect("read dir")
            .filter_map(|entry| entry.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .filter(|name| name.starts_with(".ahl-cli."))
            .collect()
    }

    #[test]
    fn a_failed_install_removes_its_temporary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("out.json");
        install(&path, b"first", Force::No).expect("fresh install");
        let _ = install(&path, b"second", Force::No).expect_err("clobber refused");
        assert!(temporaries(dir.path()).is_empty());
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
    fn a_symlinked_directory_is_refused_rather_than_traversed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real");
        std::fs::create_dir(&real).expect("mkdir");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert!(Dir::open(&link).is_err(), "O_NOFOLLOW must refuse a symlinked directory");
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

    #[test]
    fn temporary_names_are_unpredictable_and_never_repeat() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..64 {
            assert!(seen.insert(temp_name()), "a temporary name repeated");
        }
        // Nothing derivable from the process id alone: two names differ in more than a counter.
        let first = temp_name();
        let second = temp_name();
        assert_ne!(first, second);
        assert!(first.starts_with(".ahl-cli."));
    }

    #[test]
    fn a_planted_symlink_at_the_temporary_name_cannot_redirect_the_write() {
        // The name is unpredictable, so this plants one at *every* name the create could use by
        // making the directory itself unwritable for new entries — the observable property is
        // that `O_EXCL` refuses an existing entry rather than following it.
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = Dir::open(dir.path()).expect("open");
        let outside = dir.path().join("outside.txt");
        std::os::unix::fs::symlink(&outside, dir.path().join("planted")).expect("symlink");

        // Installing *at* the planted name must not write through the symlink.
        let error = handle
            .install(OsStr::new("planted"), b"attacker-controlled", Force::No)
            .expect_err("planted name refused");
        assert!(error.to_string().contains("already exists"), "{error}");
        assert!(!outside.exists(), "the write followed a symlink out of the directory");
    }

    #[test]
    fn replace_overwrites_but_read_refuses_a_symlinked_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = Dir::create(&dir.path().join("cache")).expect("create");
        handle.install(OsStr::new("a"), b"first", Force::No).expect("install");
        handle.replace(OsStr::new("a"), b"second").expect("replace");
        assert_eq!(handle.read(OsStr::new("a"), 1024).as_deref(), Some(&b"second"[..]));

        std::os::unix::fs::symlink("/etc/hosts", handle.path().join("linked")).expect("symlink");
        assert!(handle.read(OsStr::new("linked"), 1024).is_none(), "a symlink is never read");
    }

    #[test]
    fn read_is_bounded_and_absent_entries_are_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = Dir::open(dir.path()).expect("open");
        handle.install(OsStr::new("a"), &[b'x'; 32], Force::No).expect("install");
        assert_eq!(handle.read(OsStr::new("a"), 32).map(|b| b.len()), Some(32));
        assert!(handle.read(OsStr::new("a"), 31).is_none(), "over the cap is a miss");
        assert!(handle.read(OsStr::new("absent"), 32).is_none());
    }

    #[test]
    fn entries_lists_regular_files_and_remove_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = Dir::open(dir.path()).expect("open");
        handle.install(OsStr::new("a"), b"aa", Force::No).expect("install");
        handle.install(OsStr::new("b"), b"bbbb", Force::No).expect("install");
        std::os::unix::fs::symlink("/etc/hosts", dir.path().join("c")).expect("symlink");

        let names: Vec<OsString> = handle.entries().into_iter().map(|(name, _, _)| name).collect();
        assert_eq!(names.len(), 2, "a symlink is not a regular file: {names:?}");

        handle.remove(OsStr::new("a"));
        handle.remove(OsStr::new("a"));
        assert_eq!(handle.entries().len(), 1);
        assert_eq!(handle.path(), dir.path());
    }

    #[test]
    fn creating_a_directory_under_a_regular_file_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").expect("write");
        assert!(Dir::create(&file.join("cache")).is_err());
        assert!(Dir::open(&file).is_err());
    }

    #[test]
    fn every_component_create_makes_is_created_by_this_module_and_is_owner_only() {
        // The directories are created here, component by component under a handle this process
        // already holds — not by a path-based helper that resolves the whole name once to
        // create it and a second time to open it, leaving a window in which the two need not
        // land on the same directory. The mode is the visible half of that: 0700 is what
        // `mkdirat` is asked for here, where a path-based create would leave whatever the
        // process umask happens to allow.
        let dir = tempfile::tempdir().expect("tempdir");
        let deep = dir.path().join("a").join("b").join("c");
        let handle = Dir::create(&deep).expect("created");

        for level in [dir.path().join("a"), dir.path().join("a").join("b"), deep.clone()] {
            let mode = std::fs::metadata(&level).expect("metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{} is not owner-only: {mode:o}", level.display());
        }

        // And the handle is usable: writes land inside the directory that was created.
        handle.install(OsStr::new("entry"), b"payload", Force::No).expect("install");
        assert_eq!(std::fs::read(deep.join("entry")).expect("read"), b"payload");

        // Creating it again is idempotent and yields a handle to the same directory.
        let again = Dir::create(&deep).expect("already there");
        assert_eq!(again.read(OsStr::new("entry"), 64).as_deref(), Some(&b"payload"[..]));
    }

    #[test]
    fn create_refuses_a_symlinked_final_component_and_follows_an_intermediate_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real");
        std::fs::create_dir(&real).expect("mkdir");

        // The directory every later write lands in is never reached through a symlink.
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert!(Dir::create(&link).is_err(), "a symlinked final component must be refused");

        // An intermediate one is followed, deliberately: platform temporary directories
        // routinely sit behind a symlink, and refusing those would fail closed on ordinary
        // configurations rather than on hostile ones.
        let handle = Dir::create(&link.join("under")).expect("intermediate symlinks are followed");
        handle.install(OsStr::new("entry"), b"payload", Force::No).expect("install");
        assert_eq!(std::fs::read(real.join("under").join("entry")).expect("read"), b"payload");
    }

    #[test]
    fn a_component_that_cannot_be_created_is_named_rather_than_reported_as_a_missing_handle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let closed = dir.path().join("closed");
        std::fs::create_dir(&closed).expect("mkdir");
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o500)).expect("mode");

        let error = Dir::create(&closed.join("under")).expect_err("no write permission");
        assert!(error.to_string().contains("cannot create `under`"), "{error}");

        // Restored so the temporary directory can be cleaned up.
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).expect("mode");
    }

    #[test]
    fn a_relative_path_is_created_and_opened_the_same_way() {
        let dir = tempfile::tempdir().expect("tempdir");
        // `.` and `..` steps are ordinary components of the walk, not special cases.
        let path = dir.path().join("x").join(".").join("..").join("y");
        let handle = Dir::create(&path).expect("created");
        handle.install(OsStr::new("entry"), b"payload", Force::No).expect("install");
        assert_eq!(std::fs::read(dir.path().join("y").join("entry")).expect("read"), b"payload");
    }
}
