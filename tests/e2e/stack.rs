//! Process supervision for the live stack: build, start, wait, tear down.
//!
//! Three server processes and no mocks. Every binary is built from its own checkout with
//! `cargo build --release` and reused between runs; nothing here vendors a copy or shells out
//! to a package manager.
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

/// The sibling checkouts this pilot runs against, relative to this crate's manifest directory.
const ATL_SERVER: &str = "../../evidentum.io/atl-server";
const MIRROR: &str = "../ahl-mirror";
const WITNESS: &str = "../ahl-witness";

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

/// Build one checkout in release and return the path of the named binary.
///
/// The binary is reused between runs: `cargo build` is a no-op once the checkout is unchanged.
pub fn build(relative: &str, binary: &str) -> Result<PathBuf, String> {
    let root = checkout(relative);
    if !root.is_dir() {
        return Err(format!("checkout `{}` is absent", root.display()));
    }
    let status = Command::new(env!("CARGO"))
        .args(["build", "--release", "--bin", binary])
        .current_dir(&root)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|source| format!("cannot run cargo in `{}`: {source}", root.display()))?;
    if !status.success() {
        return Err(format!("`cargo build --release` failed in `{}`", root.display()));
    }
    let path = root.join("target/release").join(binary);
    if path.is_file() {
        Ok(path)
    } else {
        Err(format!("`{}` was not produced", path.display()))
    }
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
pub fn build_all() -> Result<(PathBuf, PathBuf, PathBuf), String> {
    Ok((
        build(ATL_SERVER, "atl-server")?,
        build(MIRROR, "ahl-mirror")?,
        build(WITNESS, "ahl-witness")?,
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
    let (log_binary, mirror_binary, witness_binary) = build_all()?;
    let dir = tempfile::tempdir()
        .map_err(|source| format!("cannot create a scratch directory: {source}"))?;
    let root = dir.path().to_path_buf();

    let log = start_log(&root, &log_binary, free_port(), tree_uuid, log_signing_key)?;
    let mirror = start_health_server(&root, &mirror_binary, "mirror", free_port(), mirror_config)?;
    let mut witnesses = BTreeMap::new();
    for (witness_id, config) in witness_configs {
        let server = start_health_server(&root, &witness_binary, witness_id, free_port(), config)?;
        witnesses.insert(witness_id.clone(), server);
    }
    Ok(Stack { dir, log, mirror, witnesses })
}

/// Whether the pilot may run at all: the three checkouts and the profile document must be here.
pub fn preflight(profile: &Path) -> Result<(), String> {
    for relative in [ATL_SERVER, MIRROR, WITNESS] {
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
