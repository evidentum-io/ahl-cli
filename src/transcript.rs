//! A fixed recorded network transcript, replayed as a [`Fetcher`].
//!
//! Design note §5 states a mandatory invariant — cold cache, warm cache and adversarially
//! poisoned cache produce identical verdicts and identical exit codes — and then states why it
//! has to be evaluated against a recorded transcript rather than a live endpoint: a live
//! endpoint's state changes between runs, so "identical" would not be a property of the CLI at
//! all. The transcript is therefore a first-class input, not test scaffolding.
//!
//! A transcript is a JSON document:
//!
//! ```json
//! {
//!   "description": "informative",
//!   "exchanges": [
//!     { "method": "GET",  "url": "https://mirror.example/v1/checkpoints/8",
//!       "status": 200, "body": "{...}" },
//!     { "method": "POST", "url": "https://mirror.example/v1/range",
//!       "request_body": "{...}", "status": 200, "body_base64": "eyJ9" },
//!     { "method": "GET",  "url": "https://mirror.example/v1/entries/x",
//!       "failure": "unreachable", "detail": "connection refused" }
//!   ]
//! }
//! ```
//!
//! Lookup is by `(method, url, request body)` — the same triple a cache key binds — and an
//! exchange is **not consumed** by being replayed, so the same request always produces the
//! same answer however many times a run issues it. A request the transcript does not record is
//! an unreachable endpoint, never a silent success.

use std::collections::HashMap;
use std::path::Path;

use base64::Engine as _;
use serde::Deserialize;

use crate::error::{CliError, CliResult};
use crate::net::{FetchFailure, Fetcher, Request, Response};
use crate::secure;

/// Byte cap on a transcript file.
const TRANSCRIPT_CAP: usize = 64 << 20;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TranscriptFile {
    #[serde(default)]
    #[allow(dead_code)]
    description: String,
    exchanges: Vec<Exchange>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    method: String,
    url: String,
    #[serde(default)]
    request_body: Option<String>,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    body_base64: Option<String>,
    #[serde(default)]
    failure: Option<String>,
    #[serde(default)]
    detail: Option<String>,
}

#[derive(Debug, Clone)]
enum Recorded {
    Answer(Response),
    Refused(String),
    Unreachable(String),
}

/// A replayable transcript.
#[derive(Debug)]
pub struct TranscriptFetcher {
    exchanges: HashMap<(String, String, Vec<u8>), Recorded>,
}

fn key(method: &str, url: &str, body: &[u8]) -> (String, String, Vec<u8>) {
    (method.to_owned(), url.to_owned(), body.to_vec())
}

impl TranscriptFetcher {
    /// Read a transcript from disk.
    ///
    /// # Errors
    ///
    /// [`CliError::Open`] if the file cannot be read; [`CliError::Malformed`] if it does not
    /// parse or an exchange is neither an answer nor a failure.
    pub fn load(path: &Path) -> CliResult<Self> {
        let bytes = secure::read_regular("network transcript", path, TRANSCRIPT_CAP)?;
        Self::from_slice(&bytes)
    }

    /// Parse a transcript from bytes.
    ///
    /// # Errors
    ///
    /// [`CliError::Malformed`] if the document does not parse or an exchange is ill-formed.
    pub fn from_slice(bytes: &[u8]) -> CliResult<Self> {
        let malformed = |detail: String| CliError::Malformed { what: "network transcript", detail };
        let file: TranscriptFile = serde_json::from_slice(bytes)
            .map_err(|source| malformed(format!("cannot parse: {source}")))?;

        let mut exchanges = HashMap::new();
        for exchange in file.exchanges {
            let request_body = exchange.request_body.unwrap_or_default().into_bytes();
            let recorded = match (exchange.failure.as_deref(), exchange.status) {
                (Some("refused"), None) => {
                    Recorded::Refused(exchange.detail.unwrap_or_else(|| "refused".to_owned()))
                }
                (Some("unreachable"), None) => Recorded::Unreachable(
                    exchange.detail.unwrap_or_else(|| "unreachable".to_owned()),
                ),
                (Some(other), _) => {
                    return Err(malformed(format!(
                        "exchange for `{}` declares failure `{other}`, which is neither \
                         `refused` nor `unreachable`",
                        exchange.url
                    )))
                }
                (None, Some(status)) => {
                    let body = match (exchange.body, exchange.body_base64) {
                        (Some(_), Some(_)) => {
                            return Err(malformed(format!(
                                "exchange for `{}` carries both `body` and `body_base64`",
                                exchange.url
                            )))
                        }
                        (Some(text), None) => text.into_bytes(),
                        (None, Some(encoded)) => base64::engine::general_purpose::STANDARD
                            .decode(encoded)
                            .map_err(|source| {
                                malformed(format!(
                                    "exchange for `{}` carries unparseable base64: {source}",
                                    exchange.url
                                ))
                            })?,
                        (None, None) => Vec::new(),
                    };
                    Recorded::Answer(Response { status, body })
                }
                (None, None) => {
                    return Err(malformed(format!(
                        "exchange for `{}` carries neither a status nor a failure",
                        exchange.url
                    )))
                }
            };
            exchanges.insert(key(&exchange.method, &exchange.url, &request_body), recorded);
        }
        Ok(Self { exchanges })
    }

    /// How many distinct exchanges this transcript records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.exchanges.len()
    }

    /// Whether the transcript records nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exchanges.is_empty()
    }
}

impl Fetcher for TranscriptFetcher {
    fn fetch(&self, request: &Request) -> Result<Response, FetchFailure> {
        let body = request.body.clone().unwrap_or_default();
        match self.exchanges.get(&key(request.method.as_str(), &request.url, &body)) {
            // Replaying does not consume: an operation that issues the same request twice
            // gets the same answer twice, which is what makes the cache invariant testable.
            Some(Recorded::Answer(response)) => Ok(response.clone()),
            Some(Recorded::Refused(detail)) => {
                Err(FetchFailure::Refused { url: request.url.clone(), detail: detail.clone() })
            }
            Some(Recorded::Unreachable(detail)) => {
                Err(FetchFailure::Unreachable { url: request.url.clone(), detail: detail.clone() })
            }
            // Never a silent success: an unrecorded request is an endpoint that did not answer.
            None => Err(FetchFailure::Unreachable {
                url: request.url.clone(),
                detail: "the recorded transcript has no exchange for this request".to_owned(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"{
        "description": "two answers and one failure",
        "exchanges": [
            { "method": "GET", "url": "https://m/v1/checkpoints/8", "status": 200,
              "body": "{\"tree_size\":8}" },
            { "method": "POST", "url": "https://m/v1/range",
              "request_body": "{\"from\":0}", "status": 200, "body_base64": "eyJhIjoxfQ==" },
            { "method": "GET", "url": "https://m/v1/gone",
              "failure": "unreachable", "detail": "connection refused" }
        ]
    }"#;

    fn transcript() -> TranscriptFetcher {
        TranscriptFetcher::from_slice(DOC.as_bytes()).expect("well-formed transcript")
    }

    #[test]
    fn a_recorded_get_is_replayed() {
        let response =
            transcript().fetch(&Request::get("https://m/v1/checkpoints/8")).expect("recorded");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"{\"tree_size\":8}");
    }

    #[test]
    fn a_post_is_keyed_on_its_body_too() {
        let fetcher = transcript();
        let response = fetcher
            .fetch(&Request::post("https://m/v1/range", b"{\"from\":0}".to_vec()))
            .expect("recorded");
        assert_eq!(response.body, b"{\"a\":1}");
        assert!(fetcher
            .fetch(&Request::post("https://m/v1/range", b"{\"from\":9}".to_vec()))
            .is_err());
    }

    #[test]
    fn replaying_does_not_consume_the_exchange() {
        let fetcher = transcript();
        let first = fetcher.fetch(&Request::get("https://m/v1/checkpoints/8")).expect("first");
        let second = fetcher.fetch(&Request::get("https://m/v1/checkpoints/8")).expect("second");
        assert_eq!(first, second);
    }

    #[test]
    fn a_recorded_failure_is_replayed_as_a_failure() {
        let failure = transcript().fetch(&Request::get("https://m/v1/gone")).expect_err("failure");
        assert!(matches!(failure, FetchFailure::Unreachable { .. }), "{failure}");
    }

    #[test]
    fn an_unrecorded_request_is_never_a_silent_success() {
        let failure =
            transcript().fetch(&Request::get("https://m/v1/never")).expect_err("unrecorded");
        assert!(failure.to_string().contains("no exchange"), "{failure}");
    }

    #[test]
    fn a_recorded_refusal_maps_to_the_refusing_outcome() {
        let doc = r#"{"exchanges":[{"method":"GET","url":"http://x/","failure":"refused",
                       "detail":"non-loopback plain HTTP"}]}"#;
        let fetcher = TranscriptFetcher::from_slice(doc.as_bytes()).expect("parses");
        let failure = fetcher.fetch(&Request::get("http://x/")).expect_err("refused");
        assert_eq!(failure.into_cli_error().outcome(), crate::outcome::Outcome::Error);
    }

    #[test]
    fn malformed_transcripts_are_refused_by_the_rule_they_break() {
        for doc in [
            r#"{"exchanges":[{"method":"GET","url":"https://m/"}]}"#,
            r#"{"exchanges":[{"method":"GET","url":"https://m/","failure":"weird"}]}"#,
            r#"{"exchanges":[{"method":"GET","url":"https://m/","status":200,
                 "body":"a","body_base64":"YQ=="}]}"#,
            r#"{"exchanges":[{"method":"GET","url":"https://m/","status":200,
                 "body_base64":"!!!"}]}"#,
            r"{}",
            r"not json",
        ] {
            assert!(TranscriptFetcher::from_slice(doc.as_bytes()).is_err(), "must reject: {doc}");
        }
    }

    #[test]
    fn an_empty_transcript_is_reported_as_empty() {
        let fetcher =
            TranscriptFetcher::from_slice(br#"{"exchanges":[]}"#).expect("parses");
        assert!(fetcher.is_empty());
        assert_eq!(fetcher.len(), 0);
        assert_eq!(transcript().len(), 3);
    }

    #[test]
    fn a_transcript_loads_from_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("t.json");
        std::fs::write(&path, DOC).expect("write");
        assert_eq!(TranscriptFetcher::load(&path).expect("loads").len(), 3);
        assert!(TranscriptFetcher::load(&dir.path().join("absent.json")).is_err());
    }
}
