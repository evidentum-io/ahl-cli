//! Process supervision for the live stack: build, start, wait, tear down.
//!
//! Three server processes and no mocks.
//!
//! # Nothing here writes to a checkout
//!
//! Every binary is built from a **scratch copy** of its checkout, extracted with
//! `git archive HEAD`, with `--locked` and a scratch `CARGO_TARGET_DIR`. Building inside the
//! checkouts themselves was the previous arrangement and it was wrong twice over: it wrote a
//! `target/` into somebody's working tree, and it rewrote `atl-server`'s `Cargo.lock` — that
//! checkout carries an untracked `.cargo/config.toml` patching `atl-core` to a sibling whose
//! version no longer satisfies the manifest, so every build recorded a `[patch.unused]` stanza.
//! `git archive` carries tracked files only, so the copy has no such config, `--locked`
//! succeeds, and the checkout is untouched. The tests assert that afterwards.
//!
//! The whole stack lives in one scratch directory that is removed when [`Stack`] drops. The
//! `atl-server` checkout carries an operator's own `atl.db` and `signing.key`; this harness
//! never reads or writes either, because it passes `ATL_DATABASE_PATH` and
//! `ATL_SIGNING_KEY_PATH` pointing into the scratch directory and starts the process with a
//! cleared environment, so a stray `ATL_*` in the developer's shell cannot redirect it back.

use std::collections::BTreeMap;
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// How long a server gets to answer before the harness gives up on it.
const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// How many times a server may be restarted on a fresh port before the harness gives up.
///
/// A free port is chosen by binding and releasing, which is inherently racy: something else can
/// take it in between. Retrying is the honest answer; a fixed port would collide with whatever
/// the developer already runs.
const PORT_ATTEMPTS: usize = 5;

/// The sibling checkouts this pilot runs against, relative to this crate's manifest directory.
const ATL_SERVER: &str = "../../evidentum.io/atl-server";
const CORE: &str = "../ahl-core";
const MIRROR: &str = "../ahl-mirror";
const WITNESS: &str = "../ahl-witness";

/// Every checkout the pilot reads, in the order the pristine check reports them.
pub const CHECKOUTS: [&str; 4] = [ATL_SERVER, CORE, MIRROR, WITNESS];

/// A running server, its base URL, and the file its output went to.
pub struct Server {
    child: Child,
    /// `http://127.0.0.1:<port>` — loopback, so the design note §7 plain-HTTP carve-out applies.
    pub base: String,
    log: PathBuf,
}

impl Server {
    /// Everything the process wrote, for a failure report.
    pub fn output(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The whole stack: one ATL log, one mirror, two witnesses.
///
/// Two witnesses rather than one because the pilot rotates the witness set. A rotation proof
/// binds its checkpoint to the manifest version active immediately BEFORE the rotating
/// manifest (I-D §7.1), so the cosignature on that checkpoint has to come from the OUTGOING
/// witness — an identity the incoming one cannot supply.
pub struct Stack {
    /// Crates whose committed `Cargo.lock` did not resolve, and which were therefore built
    /// against a graph cargo picked offline rather than the one their repository committed.
    ///
    /// A run with any entry here is a **diagnostic** run: it says the stack behaves, not that
    /// the committed stack behaves. The tests refuse to pass on one unless told to.
    pub stale_locks: Vec<String>,
    /// The scratch directory holding every database, key and config. Removed on drop.
    pub dir: tempfile::TempDir,
    /// The ATL log.
    pub log: Server,
    /// The mirror serving retrieval, enumeration, checkpoints and consistency.
    pub mirror: Server,
    /// Witnesses by `witness_id`.
    pub witnesses: BTreeMap<String, Server>,
}

impl Stack {
    /// The base URL of the witness with this id.
    ///
    /// # Panics
    ///
    /// If no witness with that id was started.
    pub fn witness(&self, witness_id: &str) -> &str {
        &self.witnesses.get(witness_id).expect("a started witness").base
    }
}

/// Absolute path of a sibling checkout.
pub fn checkout(relative: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::canonicalize(&path).unwrap_or(path)
}

/// `git status --porcelain` for every checkout the pilot reads.
///
/// Captured before a run and compared after it: the harness must leave a working tree exactly
/// as it found it, and an assertion is the only way that stays true.
pub fn checkout_statuses() -> BTreeMap<String, String> {
    CHECKOUTS
        .into_iter()
        .map(|relative| {
            let root = checkout(relative);
            let status = Command::new("git")
                .args(["-C", &root.display().to_string(), "status", "--porcelain"])
                .output()
                .map_or_else(
                    |source| format!("<git status failed: {source}>"),
                    |output| String::from_utf8_lossy(&output.stdout).into_owned(),
                );
            (relative.to_owned(), status)
        })
        .collect()
}

/// The git tree object of a checkout's `HEAD` — what `git archive HEAD` will extract.
///
/// The build cache is keyed on it, so a rebuild happens when and only when the committed source
/// changes. Uncommitted work in a checkout is deliberately invisible here: `git archive` would
/// not carry it either, and a cache key that claimed otherwise would be lying.
fn head_tree(relative: &str) -> Result<String, String> {
    let root = checkout(relative);
    let output = Command::new("git")
        .args(["-C", &root.display().to_string(), "rev-parse", "HEAD^{tree}"])
        .output()
        .map_err(|source| format!("cannot run git in `{}`: {source}", root.display()))?;
    if !output.status.success() {
        return Err(format!("`{}` has no HEAD to archive", root.display()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Extract a checkout's committed tree into `dest`.
///
/// `git archive` rather than a copy: it carries tracked files only, so nothing untracked — a
/// local `.cargo/config.toml`, a database, a signing key, a `target/` — reaches the build.
fn archive_into(relative: &str, dest: &Path) -> Result<(), String> {
    let root = checkout(relative);
    std::fs::create_dir_all(dest)
        .map_err(|source| format!("cannot create `{}`: {source}", dest.display()))?;
    let tarball = dest.join(".source.tar");
    let output = Command::new("git")
        .args([
            "-C",
            &root.display().to_string(),
            "archive",
            "--format=tar",
            "-o",
            &tarball.display().to_string(),
            "HEAD",
        ])
        .output()
        .map_err(|source| format!("cannot run git in `{}`: {source}", root.display()))?;
    if !output.status.success() {
        return Err(format!(
            "`git archive` failed in `{}`: {}",
            root.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let status = Command::new("tar")
        .args(["-xf", &tarball.display().to_string(), "-C", &dest.display().to_string()])
        .status()
        .map_err(|source| format!("cannot run tar: {source}"))?;
    let _ = std::fs::remove_file(&tarball);
    if status.success() {
        Ok(())
    } else {
        Err(format!("`tar -xf` failed extracting `{relative}`"))
    }
}

/// Build one binary from a scratch copy, preferring the committed dependency graph.
///
/// `--locked` first, because a pilot should run against the graph the repositories committed.
/// It is not the guarantee that keeps a checkout pristine, though — the scratch copy is — so a
/// lock that merely needs regenerating is not a reason to refuse to run. That happens routinely
/// here: `ahl-mirror` and `ahl-witness` depend on `../ahl-core` by path, so a version bump in
/// `ahl-core` makes both their committed locks stale until someone regenerates them, and the
/// harness would otherwise be unusable for the whole of that window.
///
/// The fallback is `--offline`, never a plain build: the lock is updated inside the copy, no
/// network is consulted, and the run says on stderr which graph it used and why. A build that
/// fails for any other reason is reported with cargo's own output and not retried.
fn build_binary(
    source: &Path,
    target: &Path,
    binary: &str,
    stale: &mut Vec<String>,
) -> Result<(), String> {
    let attempt = |flag: &str| {
        Command::new(env!("CARGO"))
            .args(["build", "--release", flag, "--bin", binary])
            .current_dir(source)
            .env("CARGO_TARGET_DIR", target)
            .stdout(Stdio::null())
            .output()
            .map_err(|source| format!("cannot run cargo for `{binary}`: {source}"))
    };
    let locked = attempt("--locked")?;
    if locked.status.success() {
        return Ok(());
    }
    let complaint = String::from_utf8_lossy(&locked.stderr).into_owned();
    if !complaint.contains("--locked was passed") && !complaint.contains("cannot update the lock") {
        return Err(format!(
            "`cargo build --release --locked` failed for `{binary}`:\n{complaint}"
        ));
    }
    eprintln!(
        "note: `{binary}`'s committed Cargo.lock is stale against its path dependencies, so the \
         pilot resolved offline inside its scratch copy instead. The checkout is untouched \
         either way, but the dependency graph is no longer the committed one. cargo said:\n\
         {complaint}"
    );
    stale.push(binary.to_owned());
    let offline = attempt("--offline")?;
    if offline.status.success() {
        Ok(())
    } else {
        Err(format!(
            "`cargo build --release --offline` failed for `{binary}`:\n{}",
            String::from_utf8_lossy(&offline.stderr)
        ))
    }
}

/// Where built binaries are cached between runs, keyed by the source they were built from.
///
/// The path is predictable, which is the whole problem a cache at a shared temporary location
/// has: anything that can create it first, or write into it, chooses what this harness
/// **executes**. [`open_cache_root`] is what makes it safe to use, and it refuses rather than
/// degrades.
fn cache_path() -> PathBuf {
    std::env::temp_dir().join("ahl-cli-e2e-build")
}

/// Open the cache root, creating it owner-only, and refuse it if it is not ours alone.
///
/// The checks are made on the **open handle**, not on the path, so a directory swapped between
/// the check and the use is not the one validated. A root that fails any of them is not
/// repaired and not used: the caller falls back to a per-run directory, because a cache whose
/// provenance is in question is worth less than the time it saves.
///
/// Returns `None` when the cache is unusable, with the reason on stderr.
fn open_cache_root() -> Option<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};

    let path = cache_path();
    // `create` fails if it already exists, which is the point: when we create it, the mode is
    // ours. When it exists, everything below decides whether to trust it.
    let _ = std::fs::DirBuilder::new().mode(0o700).create(&path);
    let refuse = |reason: &str| -> Option<PathBuf> {
        eprintln!(
            "note: the build cache at `{}` is not usable ({reason}); building into a per-run \
             directory instead",
            path.display()
        );
        None
    };
    // A symlink here would have the handle below land somewhere else entirely.
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => return refuse("it is a symlink"),
        Ok(_) => {}
        Err(source) => return refuse(&format!("it cannot be inspected: {source}")),
    }
    let handle = match std::fs::File::open(&path) {
        Ok(handle) => handle,
        Err(source) => return refuse(&format!("it cannot be opened: {source}")),
    };
    let metadata = match handle.metadata() {
        Ok(metadata) => metadata,
        Err(source) => return refuse(&format!("its handle cannot be inspected: {source}")),
    };
    if !metadata.is_dir() {
        return refuse("it is not a directory");
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return refuse("it is owned by another user");
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return refuse("it is readable or writable beyond its owner");
    }
    Some(path)
}

/// What a cached binary must prove about itself before it is executed.
///
/// Two independent facts, both recorded when the binary was built: the source it was built from
/// (the group's `HEAD` tree key) and the bytes it consists of. The directory permissions are the
/// control that keeps them meaningful; these turn "a file exists at the expected path" — which
/// is all the previous version checked, and is not a property of the binary at all — into "this
/// is the artifact this harness produced from that source".
fn provenance_path(binary: &Path) -> PathBuf {
    binary.with_extension("provenance")
}

/// Record what a freshly built binary is, beside it.
fn record_provenance(binary: &Path, key: &str) -> Result<(), String> {
    let digest = digest_of(binary)?;
    std::fs::write(provenance_path(binary), format!("{key}\n{digest}\n"))
        .map_err(|source| format!("cannot record provenance for `{}`: {source}", binary.display()))
}

/// The SHA-256 of a file, as hex.
fn digest_of(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path)
        .map_err(|source| format!("cannot read `{}`: {source}", path.display()))?;
    Ok(ahl_core::sha256_hex(&bytes))
}

/// Whether a cached binary may be executed: right source, right bytes, right owner.
///
/// Anything that does not answer yes is rebuilt. This is deliberately silent about *why* in the
/// common case — a cache miss is not an event — but never silently accepts.
fn provenance_holds(binary: &Path, key: &str) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let Ok(metadata) = std::fs::symlink_metadata(binary) else { return false };
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return false;
    }
    let Ok(recorded) = std::fs::read_to_string(provenance_path(binary)) else { return false };
    let mut lines = recorded.lines();
    let (Some(recorded_key), Some(recorded_digest)) = (lines.next(), lines.next()) else {
        return false;
    };
    if recorded_key != key {
        return false;
    }
    digest_of(binary).is_ok_and(|digest| digest == recorded_digest)
}

/// Build one group of checkouts from scratch copies, and return the named binaries.
///
/// The group travels together because path dependencies do: `ahl-mirror` and `ahl-witness`
/// depend on `../ahl-core`, so the copies have to keep their siblinghood. The cache key is
/// every member's `HEAD` tree, so a change to `ahl-core` rebuilds the two that depend on it.
fn build_group(
    label: &str,
    members: &[&'static str],
    binaries: &[(&'static str, &'static str)],
    cache: Option<&Path>,
    scratch: &Path,
    stale: &mut Vec<String>,
) -> Result<BTreeMap<String, PathBuf>, String> {
    let mut key = String::from(label);
    for member in members {
        key.push('-');
        key.push_str(&head_tree(member)?);
    }
    let root = cache.map_or_else(|| scratch.join(&key), |cache| cache.join(&key));
    let target = root.join("target");
    let built: BTreeMap<String, PathBuf> = binaries
        .iter()
        .map(|(_, binary)| ((*binary).to_owned(), target.join("release").join(binary)))
        .collect();
    // Reuse only what proves what it is. A file merely being present at the expected path is
    // not evidence about the file, and executing it on that basis is how a shared temporary
    // directory becomes an execution primitive for anything else on the machine.
    if cache.is_some() && built.values().all(|path| provenance_holds(path, &key)) {
        return Ok(built);
    }
    for member in members {
        let name = Path::new(member).file_name().unwrap_or_default();
        archive_into(member, &root.join("src").join(name))?;
    }
    for (member, binary) in binaries {
        let name = Path::new(member).file_name().unwrap_or_default();
        build_binary(&root.join("src").join(name), &target, binary, stale)?;
    }
    for (binary, path) in &built {
        if !path.is_file() {
            return Err(format!("`{binary}` was not produced at `{}`", path.display()));
        }
        record_provenance(path, &key)?;
    }
    Ok(built)
}

/// A free loopback port.
///
/// Bound and released, which is inherently racy; the alternative is a fixed port, which is
/// worse — it collides with whatever the developer already runs.
pub fn free_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind a loopback port");
    listener.local_addr().expect("a bound address").port()
}

/// Spawn a process with a **cleared** environment plus exactly `env`.
///
/// Clearing is the point for `atl-server`: it reads its database path and signing key from the
/// environment, and the checkout it is built from carries an operator's own copies of both.
fn spawn(
    program: &Path,
    args: &[&str],
    env: &[(&str, String)],
    cwd: &Path,
    log: &Path,
) -> Result<Child, String> {
    let file = std::fs::File::create(log)
        .map_err(|source| format!("cannot create `{}`: {source}", log.display()))?;
    let errors = file
        .try_clone()
        .map_err(|source| format!("cannot duplicate `{}`: {source}", log.display()))?;
    let mut command = Command::new(program);
    command.args(args).current_dir(cwd).stdout(file).stderr(errors).stdin(Stdio::null());
    command.env_clear();
    // `PATH` and `HOME` only: enough for a dynamic loader and a temporary directory, and
    // nothing that could redirect a server at the operator's own data.
    for (key, value) in [("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"), ("HOME", "/tmp")] {
        command.env(key, value);
    }
    for (key, value) in env {
        command.env(key, value);
    }
    command.spawn().map_err(|source| format!("cannot spawn `{}`: {source}", program.display()))
}

/// One HTTP request over a loopback socket, returned as `(status, body)`.
///
/// Deliberately not `ureq`: this is the harness's own readiness and driving channel, and it
/// must not share a code path with the client under test.
pub fn http(
    base: &str,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>), String> {
    let address: SocketAddr = base
        .trim_start_matches("http://")
        .parse()
        .map_err(|source| format!("`{base}` is not a loopback address: {source}"))?;
    let mut stream = TcpStream::connect(address)
        .map_err(|source| format!("cannot connect to `{base}`: {source}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(60))).ok();
    let payload = body.unwrap_or_default();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        payload.len()
    )
    .into_bytes();
    request.extend_from_slice(payload);
    stream.write_all(&request).map_err(|source| format!("cannot write to `{base}`: {source}"))?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|source| format!("cannot read from `{base}`: {source}"))?;
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| format!("`{base}` answered without a header terminator"))?;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| format!("`{base}` answered without a status line: {head}"))?;
    Ok((status, raw[split + 4..].to_vec()))
}

/// Wait until `probe` answers, or report what the process wrote instead.
fn wait_ready(server: &Server, probe: impl Fn() -> bool) -> Result<(), String> {
    let deadline = Instant::now() + READY_TIMEOUT;
    while Instant::now() < deadline {
        if probe() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!("`{}` never became ready; it wrote:\n{}", server.base, server.output()))
}

/// Start the ATL log with a scratch database and a scratch signing key.
///
/// `tree_uuid` fixes the Origin ID, and therefore the AHL `log_id` of adaptor §7.1, before the
/// process starts — so the manifests and the mirror and witness configurations can be written
/// against a log id the harness derived rather than one it had to ask the log for.
///
/// STANDALONE mode mounts **no** `/health` route (adaptor §10.1 records the same), so readiness
/// is probed on the anchor route: a `GET /v1/anchor/<absent uuid>` answering 404 is the router
/// running, and is the weakest probe that distinguishes "listening" from "routing".
pub fn start_log(
    dir: &Path,
    binary: &Path,
    port: u16,
    tree_uuid: &str,
    signing_key: &[u8; 32],
) -> Result<Server, String> {
    let database = dir.join("atl-db");
    let key = dir.join("atl-signing.key");
    std::fs::write(&key, signing_key)
        .map_err(|source| format!("cannot write the scratch signing key: {source}"))?;
    let env = [
        ("ATL_ROLE", "standalone".to_owned()),
        ("ATL_SERVER_HOST", Ipv4Addr::LOCALHOST.to_string()),
        ("ATL_SERVER_PORT", port.to_string()),
        ("ATL_DATABASE_PATH", database.display().to_string()),
        ("ATL_SIGNING_KEY_PATH", key.display().to_string()),
        ("ATL_TREE_UUID", tree_uuid.to_owned()),
        ("ATL_LOG_LEVEL", "warn".to_owned()),
    ];
    let child = spawn(binary, &[], &env, dir, &dir.join("atl-server.log"))?;
    let server = Server {
        child,
        base: format!("http://{}:{port}", Ipv4Addr::LOCALHOST),
        log: dir.join("atl-server.log"),
    };
    let base = server.base.clone();
    wait_ready(&server, || {
        matches!(
            http(&base, "GET", "/v1/anchor/00000000-0000-4000-8000-000000000000", None),
            Ok((404, _))
        )
    })?;
    Ok(server)
}

/// Start a server that answers `GET /health` with `ok` — the mirror and the witness both do.
fn start_health_server(
    dir: &Path,
    binary: &Path,
    name: &str,
    port: u16,
    config: &str,
) -> Result<Server, String> {
    let config_path = dir.join(format!("{name}.json"));
    std::fs::write(&config_path, config)
        .map_err(|source| format!("cannot write `{}`: {source}", config_path.display()))?;
    let log = dir.join(format!("{name}.log"));
    let listen = format!("{}:{port}", Ipv4Addr::LOCALHOST);
    let child = spawn(
        binary,
        &["--config", &config_path.display().to_string(), "--listen", &listen],
        &[("RUST_LOG", "warn".to_owned())],
        dir,
        &log,
    )?;
    let server = Server { child, base: format!("http://{listen}"), log };
    let base = server.base.clone();
    wait_ready(
        &server,
        || matches!(http(&base, "GET", "/health", None), Ok((200, body)) if body == b"ok"),
    )?;
    Ok(server)
}

/// Build every binary the pilot needs, or say which checkout is missing.
pub fn build_all(
    scratch: &Path,
    stale: &mut Vec<String>,
) -> Result<(PathBuf, PathBuf, PathBuf), String> {
    // A per-run directory is the simplest safe answer and is what `AHL_E2E_NO_CACHE=1` selects.
    // It is not the default because the cost is not marginal: a cold `atl-server` release build
    // is minutes, not seconds, and a harness that charges that to every run is a harness people
    // stop running. The cache is kept and made to prove itself instead — owner-only directory
    // validated on its handle, and per-binary provenance — with the per-run directory as the
    // fallback whenever that validation does not hold.
    let cache = if std::env::var("AHL_E2E_NO_CACHE").ok().as_deref() == Some("1") {
        None
    } else {
        open_cache_root()
    };
    let log = build_group(
        "atl",
        &[ATL_SERVER],
        &[(ATL_SERVER, "atl-server")],
        cache.as_deref(),
        scratch,
        stale,
    )?;
    // `ahl-mirror` and `ahl-witness` are path-dependent on `../ahl-core`, so the three copies
    // keep their siblinghood and share one cache key.
    let ahl = build_group(
        "ahl",
        &[CORE, MIRROR, WITNESS],
        &[(MIRROR, "ahl-mirror"), (WITNESS, "ahl-witness")],
        cache.as_deref(),
        scratch,
        stale,
    )?;
    let get = |set: &BTreeMap<String, PathBuf>, name: &str| {
        set.get(name).cloned().ok_or_else(|| format!("`{name}` was not built"))
    };
    Ok((get(&log, "atl-server")?, get(&ahl, "ahl-mirror")?, get(&ahl, "ahl-witness")?))
}

/// Start a server, retrying on a fresh port when the one chosen was taken in between.
fn with_port_retry(
    name: &str,
    mut attempt: impl FnMut(u16) -> Result<Server, String>,
) -> Result<Server, String> {
    let mut last = String::new();
    for _ in 0..PORT_ATTEMPTS {
        let port = free_port();
        match attempt(port) {
            Ok(server) => return Ok(server),
            Err(reason) if reason.contains("in use") || reason.contains("AddrInUse") => {
                last = reason;
            }
            Err(reason) => return Err(reason),
        }
    }
    Err(format!(
        "`{name}` could not hold a free loopback port over {PORT_ATTEMPTS} attempts; the last \
         one reported: {last}"
    ))
}

/// Bring the whole stack up.
///
/// `witness_configs` maps `witness_id` to that witness's configuration document, so the caller
/// decides how many witnesses the deployment has and what each is bound to.
pub fn start(
    tree_uuid: &str,
    log_signing_key: &[u8; 32],
    mirror_config: &str,
    witness_configs: &BTreeMap<String, String>,
) -> Result<Stack, String> {
    let dir = tempfile::tempdir()
        .map_err(|source| format!("cannot create a scratch directory: {source}"))?;
    let root = dir.path().to_path_buf();
    let mut stale_locks = Vec::new();
    let (log_binary, mirror_binary, witness_binary) =
        build_all(&root.join("build"), &mut stale_locks)?;

    let log = with_port_retry("atl-server", |port| {
        start_log(&root, &log_binary, port, tree_uuid, log_signing_key)
    })?;
    let mirror = with_port_retry("ahl-mirror", |port| {
        start_health_server(&root, &mirror_binary, "mirror", port, mirror_config)
    })?;
    let mut witnesses = BTreeMap::new();
    for (witness_id, config) in witness_configs {
        let server = with_port_retry(witness_id, |port| {
            start_health_server(&root, &witness_binary, witness_id, port, config)
        })?;
        witnesses.insert(witness_id.clone(), server);
    }
    Ok(Stack { stale_locks, dir, log, mirror, witnesses })
}

/// Whether the pilot may run at all: the three checkouts and the profile document must be here.
pub fn preflight(profile: &Path) -> Result<(), String> {
    for relative in CHECKOUTS {
        let root = checkout(relative);
        if !root.join("Cargo.toml").is_file() {
            return Err(format!("sibling checkout `{}` is absent", root.display()));
        }
    }
    match std::fs::metadata(profile) {
        Ok(_) => Ok(()),
        Err(source) if source.kind() == ErrorKind::NotFound => Err(format!(
            "the adaptor profile document `{}` is absent; it is read at run time and never \
             committed to this crate, so the pilot cannot pin it",
            profile.display()
        )),
        Err(source) => Err(format!("cannot read `{}`: {source}", profile.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a stand-in build artifact and return its path.
    fn artifact(dir: &Path, bytes: &[u8]) -> PathBuf {
        let path = dir.join("some-binary");
        std::fs::write(&path, bytes).expect("write the artifact");
        path
    }

    #[test]
    fn a_cached_artifact_is_reused_only_when_it_proves_what_it_is() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let binary = artifact(dir.path(), b"the artifact this harness built");

        // Nothing recorded beside it: a file existing at the expected path is not evidence
        // about the file, and accepting it on that basis is what this check replaced.
        assert!(!provenance_holds(&binary, "key-a"));

        record_provenance(&binary, "key-a").expect("record");
        assert!(provenance_holds(&binary, "key-a"));

        // Right bytes, built from other source.
        assert!(!provenance_holds(&binary, "key-b"));

        // The bytes changed under the recorded digest. This is the case that matters: it is
        // what anything able to write into a shared temporary directory would arrange, and the
        // harness would otherwise have executed the result.
        std::fs::write(&binary, b"different bytes entirely").expect("overwrite");
        assert!(
            !provenance_holds(&binary, "key-a"),
            "an artifact whose bytes no longer match what was recorded must never be run"
        );

        // A rebuild is how it is re-established.
        record_provenance(&binary, "key-a").expect("record");
        assert!(provenance_holds(&binary, "key-a"));
    }

    #[test]
    fn a_group_builds_under_the_scratch_directory_when_no_cache_is_offered() {
        // The fallback the safety check depends on: with no usable cache root, the group builds
        // under the per-run directory, which `tempfile` creates owner-only.
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let chosen: PathBuf =
            None::<&Path>.map_or_else(|| scratch.path().join("key"), |cache| cache.join("key"));
        assert!(chosen.starts_with(scratch.path()));
    }
}
