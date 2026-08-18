//! Network behaviour: HTTPS only, no redirects, budgets counted after decompression.
//!
//! Everything a command fetches goes through the [`Fetcher`] trait, so the same code paths run
//! against a live endpoint and against a **fixed recorded transcript**
//! ([`crate::transcript`]). That is not a testing convenience: the cold/warm/poisoned-cache
//! invariant of design note §5 is meaningless against a live endpoint whose state changes
//! between runs, so the invariant is stated over a transcript and the transcript has to be a
//! first-class input.
//!
//! The rules this module enforces:
//!
//! * **HTTPS only.** `--insecure` does not exist. Plain `http://` is accepted only when the
//!   **resolved peer address** is loopback — checked on the address actually connected to, not
//!   on the hostname text. [`PinningResolver`] resolves once and hands the connector exactly
//!   those addresses, so the name cannot be re-resolved to something else between the check
//!   and the connection; that is what closes DNS rebinding.
//! * **Redirects are not followed at all.** A redirect is a fetch failure naming the location.
//!   A redirect that would leave the configured host or downgrade the scheme is stronger than
//!   that: it is a configuration the CLI refuses to attempt ([`FetchFailure::Refused`], exit
//!   `2`), while an ordinary same-origin redirect is simply missing evidence (exit `3`).
//! * **Budgets.** Response bytes are counted **after decompression** — `Content-Length` is a
//!   hint, never a bound — and [`Budgeted`] additionally caps total bytes, request count and
//!   wall-clock time across a whole operation. Because [`Budgeted`] wraps any [`Fetcher`], the
//!   same budget code runs over a transcript.

use std::collections::HashMap;
use std::io::Read as _;
use std::net::ToSocketAddrs as _;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ureq::http::Uri;
use ureq::unversioned::resolver::{ArrayVec, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

use crate::error::CliError;
use crate::policy::NetworkLimits;

/// The two verbs the AHL service surfaces use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST` with a JSON body.
    Post,
}

impl Method {
    /// The wire spelling, also used as the transcript key.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// One request. Deliberately not a builder: every field is decided by the caller's rule, not
/// accumulated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Verb.
    pub method: Method,
    /// Absolute URL.
    pub url: String,
    /// JSON request body, for `POST`.
    pub body: Option<Vec<u8>>,
    /// The untrusted request-index key this response may be cached under, if any.
    ///
    /// `None` — the default — means **never cached**. A request for the *latest* checkpoint
    /// carries `None` forever: a valid old checkpoint is a replay, and serving one from cache
    /// would answer "what is newest?" with "what was newest" (design note §5).
    pub cache_key: Option<String>,
}

impl Request {
    /// A `GET`, uncached.
    #[must_use]
    pub fn get(url: impl Into<String>) -> Self {
        Self { method: Method::Get, url: url.into(), body: None, cache_key: None }
    }

    /// A `POST` carrying a JSON body, uncached.
    #[must_use]
    pub fn post(url: impl Into<String>, body: Vec<u8>) -> Self {
        Self { method: Method::Post, url: url.into(), body: Some(body), cache_key: None }
    }

    /// Mark this request cacheable under `key`.
    ///
    /// The caller builds `key` from the **locally selected checkpoint identity** plus the
    /// request itself — see [`crate::cache::request_key`]. Binding the identity is what stops
    /// a post-equivocation cache from serving material from the wrong branch.
    #[must_use]
    pub fn cached_under(mut self, key: impl Into<String>) -> Self {
        self.cache_key = Some(key.into());
        self
    }
}

/// One response. The status is carried because a mirror's 404 or 500 is an operational
/// failure the caller reports as one — it is never refusal evidence (§7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Body bytes, after any transfer decompression.
    pub body: Vec<u8>,
}

/// Why a fetch did not produce a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchFailure {
    /// A target the CLI refuses to attempt: plain HTTP to a non-loopback peer, or a
    /// cross-host or downgrade redirect. Exit `2`.
    Refused {
        /// The URL involved.
        url: String,
        /// Why.
        detail: String,
    },
    /// The endpoint could not be reached, timed out, redirected, or answered unusably.
    /// Exit `3`: a broken server is missing evidence, not a disproved artifact.
    Unreachable {
        /// The URL involved.
        url: String,
        /// Why.
        detail: String,
    },
    /// A network or decompression budget was exhausted, with the limit named. Exit `3`.
    Budget(String),
}

impl FetchFailure {
    /// Map to the outcome-carrying error of the §6 table.
    #[must_use]
    pub fn into_cli_error(self) -> CliError {
        match self {
            Self::Refused { url, detail } => CliError::RefusedTarget { url, detail },
            Self::Unreachable { url, detail } => {
                CliError::EvidenceMissing(format!("{url}: {detail}"))
            }
            Self::Budget(detail) => CliError::LimitExhausted(detail),
        }
    }
}

impl std::fmt::Display for FetchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused { url, detail } => write!(f, "refusing to fetch `{url}`: {detail}"),
            Self::Unreachable { url, detail } => write!(f, "`{url}` unusable: {detail}"),
            Self::Budget(detail) => write!(f, "budget exhausted: {detail}"),
        }
    }
}

/// Anything that can answer a [`Request`].
pub trait Fetcher: std::fmt::Debug {
    /// Perform one request.
    ///
    /// # Errors
    ///
    /// A [`FetchFailure`] naming which of the §7 rules the attempt ran into.
    fn fetch(&self, request: &Request) -> Result<Response, FetchFailure>;
}

// ---------------------------------------------------------------------------
// Budget wrapper
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct BudgetState {
    total_bytes: u64,
    requests: u32,
}

/// Caps total bytes, request count and wall-clock time across a whole operation.
///
/// Wrapping any [`Fetcher`] rather than living inside the HTTP client is deliberate: the
/// budget rules are then exercised by transcript-driven tests, where they can be asserted
/// deterministically.
#[derive(Debug)]
pub struct Budgeted<F: Fetcher> {
    inner: F,
    limits: NetworkLimits,
    started: Instant,
    state: Mutex<BudgetState>,
}

impl<F: Fetcher> Budgeted<F> {
    /// Wrap `inner` with `limits`, starting the wall-clock budget now.
    #[must_use]
    pub fn new(inner: F, limits: NetworkLimits) -> Self {
        Self {
            inner,
            limits,
            started: Instant::now(),
            state: Mutex::new(BudgetState { total_bytes: 0, requests: 0 }),
        }
    }

    /// Bytes consumed so far, across every request.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.state.lock().map_or(u64::MAX, |state| state.total_bytes)
    }

    /// Requests issued so far.
    #[must_use]
    pub fn requests(&self) -> u32 {
        self.state.lock().map_or(u32::MAX, |state| state.requests)
    }
}

impl<F: Fetcher> Fetcher for Budgeted<F> {
    fn fetch(&self, request: &Request) -> Result<Response, FetchFailure> {
        if self.started.elapsed() > Duration::from_secs(self.limits.wall_clock_seconds) {
            return Err(FetchFailure::Budget(format!(
                "wall-clock budget of {}s exhausted",
                self.limits.wall_clock_seconds
            )));
        }
        {
            // A poisoned mutex means another thread panicked mid-accounting; the budget can no
            // longer be trusted, so the operation fails closed rather than continuing unbounded.
            let mut state = self.state.lock().map_err(|_| {
                FetchFailure::Budget("network budget accounting is unusable".to_owned())
            })?;
            state.requests = state.requests.saturating_add(1);
            if state.requests > self.limits.max_subrange_requests {
                return Err(FetchFailure::Budget(format!(
                    "request budget of {} exhausted",
                    self.limits.max_subrange_requests
                )));
            }
        }

        let response = self.inner.fetch(request)?;

        let mut state = self.state.lock().map_err(|_| {
            FetchFailure::Budget("network budget accounting is unusable".to_owned())
        })?;
        state.total_bytes = state.total_bytes.saturating_add(response.body.len() as u64);
        if state.total_bytes > self.limits.max_total_bytes {
            return Err(FetchFailure::Budget(format!(
                "total response budget of {} bytes exhausted",
                self.limits.max_total_bytes
            )));
        }
        Ok(response)
    }
}

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

/// A resolver that answers only from addresses pinned before the request was issued.
///
/// The loopback rule of §7 is checked on the address actually connected to. Resolving twice —
/// once to check, once to connect — would reopen the rebinding window the rule exists to
/// close, so the check and the connection share one resolution: [`HttpFetcher::fetch`] pins,
/// and this resolver replays.
#[derive(Debug, Default)]
struct PinningResolver {
    pinned: Mutex<HashMap<String, Vec<std::net::SocketAddr>>>,
}

impl Resolver for PinningResolver {
    fn resolve(
        &self,
        uri: &Uri,
        _config: &ureq::config::Config,
        _timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let key = authority_key(uri).ok_or(ureq::Error::HostNotFound)?;
        let pinned = self.pinned.lock().map_err(|_| ureq::Error::HostNotFound)?;
        let addresses = pinned.get(&key).ok_or(ureq::Error::HostNotFound)?;
        let first = *addresses.first().ok_or(ureq::Error::HostNotFound)?;
        let mut out: ResolvedSocketAddrs = ArrayVec::from_fn(|_| first);
        for address in addresses.iter().take(16) {
            out.push(*address);
        }
        Ok(out)
    }
}

fn authority_key(uri: &Uri) -> Option<String> {
    let host = uri.host()?;
    let port = uri.port_u16().or_else(|| match uri.scheme_str() {
        Some("https") => Some(443),
        Some("http") => Some(80),
        _ => None,
    })?;
    Some(format!("{host}:{port}"))
}

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

/// A live HTTP client obeying §7.
#[derive(Debug)]
pub struct HttpFetcher {
    agent: ureq::Agent,
    resolver: std::sync::Arc<PinningResolver>,
    max_response_bytes: u64,
    request_timeout: Duration,
}

impl HttpFetcher {
    /// Build a client under `limits`.
    #[must_use]
    pub fn new(limits: NetworkLimits) -> Self {
        let resolver = std::sync::Arc::new(PinningResolver::default());
        let config = ureq::Agent::config_builder()
            // Redirects are not followed at all, and the 3xx is handed back so the failure can
            // name the location rather than disappearing into a generic error.
            .max_redirects(0)
            .max_redirects_will_error(false)
            // A 4xx or 5xx is an operational fact the caller reports, not a transport error.
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(limits.wall_clock_seconds)))
            .user_agent(concat!("ahl-cli/", env!("CARGO_PKG_VERSION")))
            .build();
        Self {
            agent: ureq::Agent::with_parts(
                config,
                DefaultConnector::new(),
                SharedResolver(std::sync::Arc::clone(&resolver)),
            ),
            resolver,
            max_response_bytes: limits.max_response_bytes,
            request_timeout: Duration::from_secs(limits.wall_clock_seconds),
        }
    }

    /// Resolve `uri`, enforce the loopback rule for plain HTTP, and pin the result.
    fn pin(&self, uri: &Uri, url: &str) -> Result<(), FetchFailure> {
        let scheme = uri.scheme_str().unwrap_or_default();
        if scheme != "https" && scheme != "http" {
            return Err(FetchFailure::Refused {
                url: url.to_owned(),
                detail: format!("scheme `{scheme}` is not HTTPS; there is no --insecure flag"),
            });
        }
        let key = authority_key(uri).ok_or_else(|| FetchFailure::Refused {
            url: url.to_owned(),
            detail: "URL carries no host".to_owned(),
        })?;

        let addresses: Vec<std::net::SocketAddr> =
            key.to_socket_addrs().map_err(|source| FetchFailure::Unreachable {
                url: url.to_owned(),
                detail: format!("cannot resolve `{key}`: {source}"),
            })?.collect();
        if addresses.is_empty() {
            return Err(FetchFailure::Unreachable {
                url: url.to_owned(),
                detail: format!("`{key}` resolved to no addresses"),
            });
        }

        if scheme == "http" {
            // The check is on the resolved peer address, never on the hostname text: a name
            // that resolves anywhere off-loopback is refused even if it is spelled
            // `localhost`, and a name that resolves to loopback is accepted whatever it is
            // spelled.
            if let Some(off_loopback) = addresses.iter().find(|a| !a.ip().is_loopback()) {
                return Err(FetchFailure::Refused {
                    url: url.to_owned(),
                    detail: format!(
                        "plain HTTP is accepted only to a loopback peer; `{key}` resolves to \
                         {}",
                        off_loopback.ip()
                    ),
                });
            }
        }

        let mut map = self.resolver.pinned.lock().map_err(|_| FetchFailure::Unreachable {
            url: url.to_owned(),
            detail: "resolver state is unusable".to_owned(),
        })?;
        map.insert(key, addresses);
        Ok(())
    }
}

/// `Resolver` is implemented for owned values; this shares one across the agent and the
/// fetcher that pins into it.
#[derive(Debug)]
struct SharedResolver(std::sync::Arc<PinningResolver>);

impl Resolver for SharedResolver {
    fn resolve(
        &self,
        uri: &Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        self.0.resolve(uri, config, timeout)
    }
}

/// Classify a redirect: leaving the origin or downgrading the scheme is a configuration the
/// CLI refuses to attempt; anything else is an ordinary fetch failure.
fn classify_redirect(from: &Uri, url: &str, location: Option<&str>) -> FetchFailure {
    let Some(location) = location else {
        return FetchFailure::Unreachable {
            url: url.to_owned(),
            detail: "redirected with no `Location`; redirects are never followed".to_owned(),
        };
    };
    let target: Option<Uri> = location.parse().ok();
    let same_origin = target.as_ref().is_none_or(|target| {
        // A relative `Location` has no authority and therefore cannot leave the origin.
        let host_matches = target.host().is_none() || target.host() == from.host();
        let scheme_ok = match target.scheme_str() {
            None => true,
            Some("https") => true,
            Some("http") => from.scheme_str() == Some("http"),
            Some(_) => false,
        };
        host_matches && scheme_ok
    });
    if same_origin {
        FetchFailure::Unreachable {
            url: url.to_owned(),
            detail: format!("redirected to `{location}`; redirects are never followed"),
        }
    } else {
        FetchFailure::Refused {
            url: url.to_owned(),
            detail: format!(
                "redirected to `{location}`, which leaves the configured host or downgrades \
                 the scheme"
            ),
        }
    }
}

/// Whether an `io::Error` from the body reader is the client's own wire-byte limit firing.
fn wire_limit_exceeded(source: &std::io::Error) -> bool {
    source
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<ureq::Error>())
        .is_some_and(|error| matches!(error, ureq::Error::BodyExceedsLimit(_)))
}

impl Fetcher for HttpFetcher {
    fn fetch(&self, request: &Request) -> Result<Response, FetchFailure> {
        let uri: Uri = request.url.parse().map_err(|source| FetchFailure::Refused {
            url: request.url.clone(),
            detail: format!("not a URL: {source}"),
        })?;
        self.pin(&uri, &request.url)?;

        let call = match request.method {
            Method::Get => self.agent.get(&request.url).call(),
            Method::Post => self
                .agent
                .post(&request.url)
                .header("content-type", "application/json")
                .send(request.body.as_deref().unwrap_or_default()),
        };

        let mut response = call.map_err(|source| FetchFailure::Unreachable {
            url: request.url.clone(),
            detail: source.to_string(),
        })?;

        let status = response.status().as_u16();
        if (300..400).contains(&status) {
            let location =
                response.headers().get("location").and_then(|value| value.to_str().ok());
            return Err(classify_redirect(&uri, &request.url, location));
        }

        // Bytes are counted while streaming and **after decompression**; `Content-Length` is a
        // hint and is never used as the bound.
        //
        // The client's own `limit()` bounds the **wire** bytes, which is not the same budget:
        // a kilobyte of gzip expands to a megabyte of zeroes, and a bound on the compressed
        // stream would let that through. The decompressed stream is therefore bounded here, on
        // top of the wire bound, and the wire bound is kept because it caps the memory the
        // decoder is fed.
        let mut reader = response.body_mut().with_config().limit(self.max_response_bytes).reader();
        let mut body = Vec::new();
        let budget_exhausted = |detail: &str| {
            FetchFailure::Budget(format!(
                "response from `{}` exceeds the {}-byte per-response budget ({detail}, \
                 counted after decompression)",
                request.url, self.max_response_bytes
            ))
        };
        let read = (&mut reader)
            .take(self.max_response_bytes.saturating_add(1))
            .read_to_end(&mut body)
            .map_err(|source| {
                if wire_limit_exceeded(&source) {
                    budget_exhausted("compressed stream longer than the budget")
                } else {
                    FetchFailure::Unreachable {
                        url: request.url.clone(),
                        detail: source.to_string(),
                    }
                }
            })?;
        if read as u64 > self.max_response_bytes {
            return Err(budget_exhausted("decompressed stream longer than the budget"));
        }

        let _ = self.request_timeout;
        Ok(Response { status, body })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::net::TcpListener;

    use super::*;

    /// A one-shot loopback server that writes `response` verbatim and closes.
    fn one_shot(response: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut discard = [0u8; 4096];
                let _ = stream.read(&mut discard);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });
        (format!("http://127.0.0.1:{port}"), handle)
    }

    fn http_response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n{headers}\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn limits() -> NetworkLimits {
        NetworkLimits { wall_clock_seconds: 10, ..NetworkLimits::default() }
    }

    #[test]
    fn plain_http_to_a_loopback_peer_is_accepted() {
        let (url, handle) = one_shot(http_response("200 OK", "", b"{\"ok\":true}"));
        let fetcher = HttpFetcher::new(limits());
        let response = fetcher.fetch(&Request::get(format!("{url}/health"))).expect("loopback");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"{\"ok\":true}");
        handle.join().expect("server thread");
    }

    #[test]
    fn plain_http_to_a_non_loopback_peer_is_refused_before_any_connection() {
        let fetcher = HttpFetcher::new(limits());
        // 93.184.215.14 is IANA's example-address range: never loopback, never connected to
        // here because the refusal happens at resolution time.
        let failure = fetcher
            .fetch(&Request::get("http://93.184.215.14/v1/checkpoints"))
            .expect_err("non-loopback plain HTTP");
        assert!(matches!(failure, FetchFailure::Refused { .. }), "{failure}");
        assert_eq!(failure.into_cli_error().outcome(), crate::outcome::Outcome::Error);
    }

    #[test]
    fn a_non_http_scheme_is_refused() {
        let fetcher = HttpFetcher::new(limits());
        let failure =
            fetcher.fetch(&Request::get("ftp://example.invalid/x")).expect_err("bad scheme");
        assert!(matches!(failure, FetchFailure::Refused { .. }), "{failure}");
    }

    #[test]
    fn a_same_origin_redirect_is_a_fetch_failure_naming_the_location() {
        let (url, handle) = one_shot(http_response(
            "302 Found",
            "location: /v1/elsewhere\r\n",
            b"",
        ));
        let fetcher = HttpFetcher::new(limits());
        let failure = fetcher.fetch(&Request::get(format!("{url}/v1/range"))).expect_err("302");
        assert!(matches!(failure, FetchFailure::Unreachable { .. }), "{failure}");
        assert!(failure.to_string().contains("/v1/elsewhere"), "{failure}");
        assert_eq!(failure.into_cli_error().outcome(), crate::outcome::Outcome::Unverifiable);
        handle.join().expect("server thread");
    }

    #[test]
    fn a_cross_host_redirect_is_a_configuration_the_cli_refuses_to_attempt() {
        let (url, handle) = one_shot(http_response(
            "301 Moved Permanently",
            "location: https://evil.example/v1/range\r\n",
            b"",
        ));
        let fetcher = HttpFetcher::new(limits());
        let failure = fetcher.fetch(&Request::get(format!("{url}/v1/range"))).expect_err("301");
        assert!(matches!(failure, FetchFailure::Refused { .. }), "{failure}");
        assert_eq!(failure.into_cli_error().outcome(), crate::outcome::Outcome::Error);
        handle.join().expect("server thread");
    }

    #[test]
    fn a_redirect_without_a_location_is_still_a_fetch_failure() {
        let (url, handle) = one_shot(http_response("307 Temporary Redirect", "", b""));
        let fetcher = HttpFetcher::new(limits());
        let failure = fetcher.fetch(&Request::get(format!("{url}/x"))).expect_err("307");
        assert!(failure.to_string().contains("never followed"), "{failure}");
        handle.join().expect("server thread");
    }

    #[test]
    fn an_oversized_response_exhausts_the_per_response_budget() {
        let body = vec![b'x'; 4096];
        let (url, handle) = one_shot(http_response("200 OK", "", &body));
        let fetcher =
            HttpFetcher::new(NetworkLimits { max_response_bytes: 128, ..limits() });
        let failure = fetcher.fetch(&Request::get(format!("{url}/big"))).expect_err("oversized");
        assert!(matches!(failure, FetchFailure::Budget(_)), "{failure}");
        assert!(failure.to_string().contains("after decompression"), "{failure}");
        handle.join().expect("server thread");
    }

    #[test]
    fn a_decompression_bomb_is_bounded_by_the_decompressed_size_not_the_wire_size() {
        // A megabyte of zeroes compresses to about a kilobyte. `Content-Length` is a hint:
        // the budget is spent on what comes out of the decompressor.
        let payload = vec![0u8; 1 << 20];
        let mut encoder =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&payload).expect("compress");
        let compressed = encoder.finish().expect("finish");
        assert!(compressed.len() < 8192, "test fixture must be small on the wire");

        let (url, handle) =
            one_shot(http_response("200 OK", "content-encoding: gzip\r\n", &compressed));
        let fetcher =
            HttpFetcher::new(NetworkLimits { max_response_bytes: 65_536, ..limits() });
        let failure = fetcher.fetch(&Request::get(format!("{url}/bomb"))).expect_err("bomb");
        assert!(matches!(failure, FetchFailure::Budget(_)), "{failure}");
        handle.join().expect("server thread");
    }

    #[test]
    fn a_compressed_response_within_budget_is_decompressed_and_returned() {
        let payload = b"{\"entries\":[]}".repeat(64);
        let mut encoder =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&payload).expect("compress");
        let compressed = encoder.finish().expect("finish");
        let (url, handle) =
            one_shot(http_response("200 OK", "content-encoding: gzip\r\n", &compressed));
        let fetcher = HttpFetcher::new(limits());
        let response = fetcher.fetch(&Request::get(format!("{url}/ok"))).expect("within budget");
        assert_eq!(response.body, payload);
        handle.join().expect("server thread");
    }

    #[test]
    fn an_unreachable_endpoint_is_missing_evidence_not_a_verdict() {
        // Bind and immediately drop, so the port is almost certainly closed.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let fetcher = HttpFetcher::new(NetworkLimits { wall_clock_seconds: 2, ..limits() });
        let failure = fetcher
            .fetch(&Request::get(format!("http://127.0.0.1:{port}/health")))
            .expect_err("closed port");
        assert!(matches!(failure, FetchFailure::Unreachable { .. }), "{failure}");
        assert_eq!(failure.into_cli_error().outcome(), crate::outcome::Outcome::Unverifiable);
    }

    #[test]
    fn a_server_error_status_is_returned_rather_than_raised() {
        let (url, handle) = one_shot(http_response("500 Internal Server Error", "", b"nope"));
        let fetcher = HttpFetcher::new(limits());
        let response = fetcher.fetch(&Request::get(format!("{url}/x"))).expect("status returned");
        assert_eq!(response.status, 500);
        handle.join().expect("server thread");
    }

    #[test]
    fn a_malformed_url_is_refused() {
        let fetcher = HttpFetcher::new(limits());
        assert!(matches!(
            fetcher.fetch(&Request::get("not a url")).expect_err("bad url"),
            FetchFailure::Refused { .. }
        ));
    }

    #[derive(Debug)]
    struct Canned(Vec<u8>);

    impl Fetcher for Canned {
        fn fetch(&self, _request: &Request) -> Result<Response, FetchFailure> {
            Ok(Response { status: 200, body: self.0.clone() })
        }
    }

    #[test]
    fn the_total_byte_budget_is_spent_across_requests() {
        let budgeted = Budgeted::new(
            Canned(vec![0u8; 100]),
            NetworkLimits { max_total_bytes: 250, ..limits() },
        );
        assert!(budgeted.fetch(&Request::get("https://x/1")).is_ok());
        assert!(budgeted.fetch(&Request::get("https://x/2")).is_ok());
        assert_eq!(budgeted.total_bytes(), 200);
        let failure = budgeted.fetch(&Request::get("https://x/3")).expect_err("budget");
        assert!(failure.to_string().contains("total response budget"), "{failure}");
    }

    #[test]
    fn the_request_budget_is_spent_across_requests() {
        let budgeted = Budgeted::new(
            Canned(Vec::new()),
            NetworkLimits { max_subrange_requests: 2, ..limits() },
        );
        assert!(budgeted.fetch(&Request::get("https://x/1")).is_ok());
        assert!(budgeted.fetch(&Request::get("https://x/2")).is_ok());
        assert_eq!(budgeted.requests(), 2);
        let failure = budgeted.fetch(&Request::get("https://x/3")).expect_err("budget");
        assert!(failure.to_string().contains("request budget"), "{failure}");
    }

    #[test]
    fn the_wall_clock_budget_is_checked_before_each_request() {
        let budgeted =
            Budgeted::new(Canned(Vec::new()), NetworkLimits { wall_clock_seconds: 0, ..limits() });
        std::thread::sleep(Duration::from_millis(5));
        let failure = budgeted.fetch(&Request::get("https://x/1")).expect_err("budget");
        assert!(failure.to_string().contains("wall-clock"), "{failure}");
    }

    #[test]
    fn methods_render_as_their_wire_spelling() {
        assert_eq!(Method::Get.as_str(), "GET");
        assert_eq!(Method::Post.as_str(), "POST");
        assert_eq!(Request::post("https://x/y", b"{}".to_vec()).body.as_deref(), Some(&b"{}"[..]));
    }

    #[test]
    fn a_relative_redirect_location_stays_within_the_origin() {
        let from: Uri = "https://mirror.example/v1/range".parse().expect("uri");
        assert!(matches!(
            classify_redirect(&from, "https://mirror.example/v1/range", Some("/elsewhere")),
            FetchFailure::Unreachable { .. }
        ));
        assert!(matches!(
            classify_redirect(
                &from,
                "https://mirror.example/v1/range",
                Some("http://mirror.example/v1/range"),
            ),
            FetchFailure::Refused { .. }
        ));
    }
}
