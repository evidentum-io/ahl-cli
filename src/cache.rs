//! The optional two-layer cache, and why it has two layers.
//!
//! A "content hashes only" cache is unimplementable: a range response or a checkpoint has no
//! digest known before it is fetched, so there is nothing to look it up by. The cache is
//! therefore split:
//!
//! * an **object store**, keyed by the digest of the stored bytes;
//! * an **untrusted request index**, mapping a request key to a digest.
//!
//! The request key binds the **locally selected checkpoint identity** `{log_id, tree_size,
//! root_hash}`, not merely endpoint and range. After an equivocation two distinct roots exist
//! at one `tree_size`, so a key built from endpoint + range + size would serve material from
//! the wrong branch — see [`request_key`].
//!
//! # The index has zero evidentiary weight, and the digest check is not what enforces that
//!
//! [`Cache::get`] recomputes the digest of the stored bytes and compares it with the digest
//! the index selected. That is an **integrity check on storage** — it catches a corrupted or
//! half-written object. It says nothing whatever about whether the bytes are the right answer:
//! an attacker with write access to the cache directory can store arbitrary bytes under their
//! own matching digest and point an index entry at them, and every digest check will pass.
//!
//! What actually enforces the invariant is that the caller re-runs the same proof checks a
//! fresh response would get, against the **locally selected** root, and — on failure — evicts
//! and refetches exactly once through [`crate::net::fetch_revalidating`]. A poisoned cache can
//! therefore change *what work happens*, never *what is accepted*.
//!
//! Consequences that follow, and are tested:
//!
//! * a request for the *latest* checkpoint is never served from cache (a valid old checkpoint
//!   is a replay) — expressed by such requests carrying no `cache_key` at all;
//! * a cached object failing **semantic** re-verification is evicted and refetched once, then
//!   reported;
//! * the store is bounded by a byte quota and evicts least-recently-used, so a long
//!   enumeration cannot fill the disk.
//!
//! # Storing is a separate verb from fetching, and that is what makes the retry honest
//!
//! [`Caching::fetch`] never writes. A response reaches the store only through
//! [`Caching::store`], which [`crate::net::fetch_revalidating`] calls **after** the caller's
//! own proof checks have accepted it.
//!
//! The rule the split enforces is that a request is repeated only when the answer it refused
//! really came out of the cache. Writing a live answer the moment it arrived would file bytes
//! nobody had verified under the request key; the eviction that follows a refusal would then
//! report `true`, and the caller would go back to a live endpoint that had simply answered
//! badly — a repeat request earned by a cache entry the same run had just manufactured. With
//! nothing stored until it verifies, an eviction can only ever have removed a genuinely cached
//! answer, and a broken server is reported rather than hammered.
//!
//! # Writes
//!
//! Every write goes through [`crate::install::Dir`]: handle-relative, `O_NOFOLLOW`, an
//! `O_EXCL` temporary under an unpredictable name, and a no-replace install. A cache entry has
//! no evidentiary weight, but that was never a licence to let a symlink planted in the cache
//! directory redirect a write outside it.

use std::ffi::OsString;
use std::path::Path;
use std::time::SystemTime;

use ahl_core::sha256_hex;

use crate::error::CliResult;
use crate::install::{Dir, Force};
use crate::net::{FetchFailure, Fetcher, Request, Response};

/// The locally selected checkpoint identity a cache key binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointIdentity {
    /// `log_id`, as `sha256:<hex>`.
    pub log_id: String,
    /// Number of entries the checkpoint commits.
    pub tree_size: u64,
    /// `root_hash`, as `sha256:<hex>`.
    pub root_hash: String,
}

/// Build the untrusted request-index key for one request under one selected checkpoint.
///
/// The identity is part of the key, so two branches of an equivocating log never share an
/// entry: same endpoint, same range, same `tree_size`, different `root_hash` — different key.
#[must_use]
pub fn request_key(identity: &CheckpointIdentity, request: &Request) -> String {
    let body = request.body.as_deref().unwrap_or_default();
    let material = format!(
        "ahl-cli/1\n{}\n{}\n{}\n{}\n{}\n{}",
        identity.log_id,
        identity.tree_size,
        identity.root_hash,
        request.method.as_str(),
        request.url,
        sha256_hex(body),
    );
    sha256_hex(material.as_bytes())
}

/// A two-layer on-disk cache.
#[derive(Debug)]
pub struct Cache {
    objects: Dir,
    index: Dir,
    quota_bytes: u64,
}

impl Cache {
    /// Open (creating if needed) a cache under `dir`, bounded by `quota_bytes`.
    ///
    /// # Errors
    ///
    /// [`crate::error::CliError::Output`] if the directories cannot be created or are not
    /// directories.
    pub fn open(dir: &Path, quota_bytes: u64) -> CliResult<Self> {
        Ok(Self {
            objects: Dir::create(&dir.join("objects"))?,
            index: Dir::create(&dir.join("index"))?,
            quota_bytes,
        })
    }

    fn read_cap(&self) -> usize {
        usize::try_from(self.quota_bytes).unwrap_or(usize::MAX)
    }

    /// Look up `key`, checking the stored bytes against the digest they are filed under.
    ///
    /// A stored object whose bytes no longer hash to that digest is evicted here and reported
    /// as a miss. This is storage integrity only: see the module docs for why it is not, and
    /// cannot be, verification.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let name = sanitize(key);
        let digest = String::from_utf8(self.index.read(&name, 128)?).ok()?;
        let digest = digest.trim().to_owned();
        let object = sanitize(&digest);
        let bytes = self.objects.read(&object, self.read_cap())?;
        if sha256_hex(&bytes) == digest {
            // Touch for the LRU. A failure here only costs eviction accuracy.
            let _ = self.objects.replace(&object, &bytes);
            Some(bytes)
        } else {
            self.objects.remove(&object);
            self.index.remove(&name);
            None
        }
    }

    /// Store `bytes` under `key`, then enforce the byte quota.
    ///
    /// # Errors
    ///
    /// [`crate::error::CliError::Output`] if the object or index entry cannot be written.
    pub fn put(&self, key: &str, bytes: &[u8]) -> CliResult<()> {
        let digest = sha256_hex(bytes);
        let object = sanitize(&digest);
        // Objects are content-addressed and immutable, so an existing one is already correct
        // and a no-replace install refusing it is the right answer, not an error.
        if self.objects.read(&object, self.read_cap()).is_none() {
            self.objects.install(&object, bytes, Force::No)?;
        }
        // An index entry legitimately moves to a newer object, so replacement is normal here —
        // still handle-relative and still no-replace after an explicit unlink.
        self.index.replace(&sanitize(key), digest.as_bytes())?;
        self.enforce_quota();
        Ok(())
    }

    /// Remove the index entry and its object, reporting whether anything was removed.
    #[must_use]
    pub fn evict(&self, key: &str) -> bool {
        let name = sanitize(key);
        let Some(digest) = self.index.read(&name, 128) else { return false };
        if let Ok(digest) = String::from_utf8(digest) {
            self.objects.remove(&sanitize(digest.trim()));
        }
        self.index.remove(&name);
        true
    }

    /// Total bytes currently held in the object store.
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.objects.entries().iter().map(|(_, size, _)| *size).sum()
    }

    /// Drop least-recently-used objects until the store is within quota.
    fn enforce_quota(&self) {
        let mut objects: Vec<(OsString, u64, SystemTime)> = self.objects.entries();
        let mut total: u64 = objects.iter().map(|(_, size, _)| *size).sum();
        if total <= self.quota_bytes {
            return;
        }
        objects.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.0.cmp(&b.0)));
        for (name, size, _) in objects {
            if total <= self.quota_bytes {
                break;
            }
            self.objects.remove(&name);
            total = total.saturating_sub(size);
        }
    }
}

fn sanitize(key: &str) -> OsString {
    OsString::from(
        key.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect::<String>(),
    )
}

/// A [`Fetcher`] that consults a cache for requests carrying a `cache_key`.
#[derive(Debug)]
pub struct Caching<F: Fetcher> {
    inner: F,
    cache: Cache,
}

impl<F: Fetcher> Caching<F> {
    /// Wrap `inner` with `cache`.
    #[must_use]
    pub const fn new(inner: F, cache: Cache) -> Self {
        Self { inner, cache }
    }

    /// The wrapped cache, for reporting.
    #[must_use]
    pub const fn cache(&self) -> &Cache {
        &self.cache
    }
}

impl<F: Fetcher> Fetcher for Caching<F> {
    fn fetch(&self, request: &Request) -> Result<Response, FetchFailure> {
        let Some(key) = request.cache_key.as_deref() else {
            return self.inner.fetch(request);
        };
        if let Some(bytes) = self.cache.get(key) {
            // Returned with the status a successful fetch carries. The caller re-runs every
            // proof check against the locally selected root regardless, and evicts through
            // `invalidate` if they fail, so this cannot decide what is accepted.
            return Ok(Response { status: 200, body: bytes });
        }
        // A live answer is **not** written here. Storing it before the caller has verified it
        // would file rejected bytes under the request key, and the eviction that follows would
        // then report `true` — telling `fetch_revalidating` that the answer it just refused had
        // come from the cache, and earning a repeat request no cached answer ever justified.
        // The write happens in `store`, after verification.
        self.inner.fetch(request)
    }

    fn invalidate(&self, request: &Request) -> bool {
        // Only a genuine eviction reports `true`: that is what stops a caller from retrying a
        // live endpoint that simply answered badly. Since nothing is stored until it has
        // verified, `true` here means the refused answer really was a cached one.
        request.cache_key.as_deref().is_some_and(|key| self.cache.evict(key))
            || self.inner.invalidate(request)
    }

    fn store(&self, request: &Request, response: &Response) {
        let Some(key) = request.cache_key.as_deref() else { return };
        if response.status != 200 {
            return;
        }
        // A cache write failure is not a verification failure: the operation continues with
        // the bytes it already has.
        let _ = self.cache.put(key, &response.body);
        self.inner.store(request, response);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::error::CliError;
    use crate::net::fetch_revalidating;

    fn identity(root: &str) -> CheckpointIdentity {
        CheckpointIdentity {
            log_id: format!("sha256:{}", "11".repeat(32)),
            tree_size: 8,
            root_hash: format!("sha256:{root}"),
        }
    }

    #[derive(Debug)]
    struct Counting {
        body: Vec<u8>,
        calls: AtomicUsize,
    }

    impl Counting {
        fn new(body: &[u8]) -> Self {
            Self { body: body.to_vec(), calls: AtomicUsize::new(0) }
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl Fetcher for Counting {
        fn fetch(&self, _request: &Request) -> Result<Response, FetchFailure> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(Response { status: 200, body: self.body.clone() })
        }
    }

    #[test]
    fn the_request_key_binds_the_selected_checkpoint_identity() {
        let request = Request::post("https://m/v1/range", b"{\"from\":0}".to_vec());
        let branch_a = request_key(&identity(&"aa".repeat(32)), &request);
        let branch_b = request_key(&identity(&"bb".repeat(32)), &request);
        assert_ne!(branch_a, branch_b, "two roots at one tree_size must not share an entry");

        let mut other_size = identity(&"aa".repeat(32));
        other_size.tree_size = 9;
        assert_ne!(branch_a, request_key(&other_size, &request));

        let other_body = Request::post("https://m/v1/range", b"{\"from\":4}".to_vec());
        assert_ne!(branch_a, request_key(&identity(&"aa".repeat(32)), &other_body));
    }

    #[test]
    fn the_request_key_is_stable_for_the_same_inputs() {
        let request = Request::get("https://m/v1/entries/x");
        let id = identity(&"aa".repeat(32));
        assert_eq!(request_key(&id, &request), request_key(&id, &request));
    }

    #[test]
    fn a_warm_cache_serves_without_a_second_fetch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(dir.path(), 1 << 20).expect("open cache");
        let caching = Caching::new(Counting::new(b"payload"), cache);
        let request = Request::get("https://m/v1/x").cached_under("k1");

        // The cold answer reaches the cache when the caller accepts it, never before.
        let cold = caching.fetch(&request).expect("cold");
        assert_eq!(cold.body, b"payload");
        assert!(caching.cache().get("k1").is_none(), "a fetch alone stores nothing");
        caching.store(&request, &cold);

        assert_eq!(caching.fetch(&request).expect("warm").body, b"payload");
        assert_eq!(caching.inner.calls(), 1, "the warm read must not reach the network");
    }

    #[test]
    fn an_uncacheable_request_always_reaches_the_network() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(dir.path(), 1 << 20).expect("open cache");
        let caching = Caching::new(Counting::new(b"latest"), cache);
        let request = Request::get("https://m/v1/checkpoints/latest");
        assert!(request.cache_key.is_none(), "the latest checkpoint is never cacheable");

        let _ = caching.fetch(&request).expect("first");
        let _ = caching.fetch(&request).expect("second");
        assert_eq!(caching.inner.calls(), 2);
        assert!(!caching.invalidate(&request), "there is nothing to evict for an uncached request");
    }

    #[test]
    fn a_corrupted_object_is_a_miss_and_is_refetched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(dir.path(), 1 << 20).expect("open cache");
        let caching = Caching::new(Counting::new(b"payload"), cache);
        let request = Request::get("https://m/v1/x").cached_under("k1");
        let cold = caching.fetch(&request).expect("cold");
        caching.store(&request, &cold);

        // Bytes that no longer hash to the digest they are filed under: storage corruption,
        // caught by the integrity check.
        for (name, _, _) in caching.cache.objects.entries() {
            caching.cache.objects.replace(&name, b"corrupted").expect("corrupt");
        }
        assert!(caching.cache.get("k1").is_none(), "a corrupted object must not be served");

        assert_eq!(caching.fetch(&request).expect("refetch").body, b"payload");
        assert_eq!(caching.inner.calls(), 2);
    }

    /// Store `bytes` under `key` **with a matching digest**, which is what an attacker with
    /// write access to the cache directory can always do. The integrity check passes; only
    /// semantic verification catches it.
    fn plant(cache: &Cache, key: &str, bytes: &[u8]) {
        cache.put(key, bytes).expect("plant");
        assert_eq!(cache.get(key).as_deref(), Some(bytes), "the plant must look genuine");
    }

    fn rejecting() -> impl Fn(&Response) -> CliResult<Vec<u8>> {
        |_: &Response| Err(CliError::EvidenceMissing("did not verify".to_owned()))
    }

    #[test]
    fn a_semantically_wrong_but_digest_consistent_object_is_evicted_and_refetched_once() {
        // The heart of the §5 invariant. The digest check cannot catch this — the bytes hash
        // to exactly the digest the index names — so eviction has to be driven by the caller's
        // own verification, through `fetch_revalidating`.
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(dir.path(), 1 << 20).expect("open cache");
        let caching = Caching::new(Counting::new(b"genuine"), cache);
        let request = Request::get("https://m/v1/x").cached_under("k1");
        plant(caching.cache(), "k1", b"attacker-controlled");

        let verify = |response: &Response| -> CliResult<Vec<u8>> {
            if response.body == b"genuine" {
                Ok(response.body.clone())
            } else {
                Err(CliError::EvidenceMissing("did not verify".to_owned()))
            }
        };
        let value = fetch_revalidating(&caching, &request, verify).expect("revalidated");
        assert_eq!(value, b"genuine", "the cold answer must survive a poisoned cache");
        assert_eq!(caching.inner.calls(), 1, "evicted and refetched exactly once");
        // And the answer that verified is the one now on disk.
        assert_eq!(caching.cache().get("k1").as_deref(), Some(&b"genuine"[..]));
    }

    #[test]
    fn a_second_failure_is_reported_rather_than_retried_forever() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(dir.path(), 1 << 20).expect("open cache");
        let caching = Caching::new(Counting::new(b"still-wrong"), cache);
        let request = Request::get("https://m/v1/x").cached_under("k1");
        plant(caching.cache(), "k1", b"attacker-controlled");

        let error = fetch_revalidating(&caching, &request, rejecting()).expect_err("reported");
        assert!(error.to_string().contains("did not verify"), "{error}");
        assert_eq!(caching.inner.calls(), 1, "exactly one refetch, then reported");
    }

    #[test]
    fn a_live_answer_that_is_refused_is_never_cached_and_never_earns_a_repeat_request() {
        // The invariant: a repeat request is earned only by an answer that really came out of
        // the cache. A live answer written to the cache *before* the caller verified it would
        // make the eviction that follows report `true`, and `fetch_revalidating` would go back
        // to a live endpoint that had simply answered badly — the request repeated on the
        // strength of a cache entry this run had just manufactured.
        //
        // The request carries a cache key and the cache is real, so nothing about this test is
        // vacuous: with an eager write it fails on the call count, and it fails again on the
        // cache holding bytes that never verified.
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(dir.path(), 1 << 20).expect("open cache");
        let caching = Caching::new(Counting::new(b"wrong"), cache);
        let request = Request::get("https://m/v1/x").cached_under("k1");
        assert!(caching.cache().get("k1").is_none(), "the cache starts cold");

        let error = fetch_revalidating(&caching, &request, rejecting()).expect_err("reported");
        assert!(error.to_string().contains("did not verify"), "{error}");
        assert_eq!(
            caching.inner.calls(),
            1,
            "a broken server is reported, not hammered: nothing came from the cache, so \
             nothing was evicted and no repeat request was earned"
        );
        assert!(
            caching.cache().get("k1").is_none(),
            "bytes the caller refused must never be filed under the request key"
        );
        assert!(!caching.invalidate(&request), "there was nothing to evict");
    }

    #[test]
    fn a_verified_answer_is_what_the_cache_comes_to_hold() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(dir.path(), 1 << 20).expect("open cache");
        let caching = Caching::new(Counting::new(b"genuine"), cache);
        let request = Request::get("https://m/v1/x").cached_under("k1");

        let accept = |response: &Response| -> CliResult<Vec<u8>> { Ok(response.body.clone()) };
        assert_eq!(fetch_revalidating(&caching, &request, accept).expect("verified"), b"genuine");
        assert_eq!(caching.cache().get("k1").as_deref(), Some(&b"genuine"[..]));

        // Warm: served from the cache, no second call.
        assert_eq!(fetch_revalidating(&caching, &request, accept).expect("warm"), b"genuine");
        assert_eq!(caching.inner.calls(), 1);
    }

    #[test]
    fn a_fetcher_with_no_cache_never_reports_an_eviction_or_stores_anything() {
        let counting = Counting::new(b"wrong");
        let request = Request::get("https://m/v1/x");
        assert!(fetch_revalidating(&counting, &request, rejecting()).is_err());
        assert_eq!(counting.calls(), 1);
        counting.store(&request, &Response { status: 200, body: b"x".to_vec() });
    }

    #[test]
    fn a_poisoned_index_pointing_at_nothing_is_a_miss_not_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(dir.path(), 1 << 20).expect("open cache");
        cache
            .index
            .replace(&sanitize("k1"), format!("sha256:{}", "ff".repeat(32)).as_bytes())
            .expect("write index");
        assert!(cache.get("k1").is_none());
    }

    #[test]
    fn eviction_removes_an_entry_and_its_object_and_reports_whether_it_did() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(dir.path(), 1 << 20).expect("open cache");
        cache.put("k1", b"payload").expect("put");
        assert!(cache.get("k1").is_some());
        assert!(cache.evict("k1"), "an eviction that removed something reports true");
        assert!(cache.get("k1").is_none());
        assert_eq!(cache.size_bytes(), 0);
        assert!(!cache.evict("k1"), "evicting an absent key reports false");
    }

    #[test]
    fn the_byte_quota_bounds_the_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(dir.path(), 300).expect("open cache");
        for n in 0u8..10 {
            cache.put(&format!("k{n}"), &[n; 100]).expect("put");
        }
        assert!(cache.size_bytes() <= 300, "quota exceeded: {} bytes", cache.size_bytes());
    }

    #[test]
    fn identical_bytes_under_two_keys_share_one_object() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(dir.path(), 1 << 20).expect("open cache");
        cache.put("k1", b"same").expect("put");
        cache.put("k2", b"same").expect("put");
        assert_eq!(cache.objects.entries().len(), 1);
        assert_eq!(cache.get("k1"), cache.get("k2"));
    }

    #[test]
    fn a_non_200_response_is_not_cached() {
        #[derive(Debug)]
        struct NotFound;
        impl Fetcher for NotFound {
            fn fetch(&self, _request: &Request) -> Result<Response, FetchFailure> {
                Ok(Response { status: 404, body: b"absent".to_vec() })
            }
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(dir.path(), 1 << 20).expect("open cache");
        let caching = Caching::new(NotFound, cache);
        let request = Request::get("https://m/v1/x").cached_under("k1");
        let response = caching.fetch(&request).expect("404");
        assert_eq!(response.status, 404);
        // Even offered explicitly, a non-200 is never filed.
        caching.store(&request, &response);
        assert!(caching.cache().get("k1").is_none());
    }

    #[test]
    fn opening_a_cache_under_an_unusable_directory_is_an_output_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").expect("write");
        assert!(Cache::open(&file, 1 << 20).is_err());
    }

    #[test]
    fn a_symlink_planted_in_the_cache_cannot_redirect_a_write_outside_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(&dir.path().join("cache"), 1 << 20).expect("open cache");
        let outside = dir.path().join("outside.txt");
        let planted = sanitize("planted");
        std::os::unix::fs::symlink(&outside, cache.index.path().join("planted")).expect("symlink");

        // Writing at the planted name must not follow it.
        let _ = cache.index.replace(&planted, b"attacker");
        assert!(
            !outside.exists() || std::fs::read(&outside).expect("read") != b"attacker",
            "a cache write followed a symlink out of the cache directory"
        );
        // And reading it back never follows it either.
        assert!(cache.index.read(&planted, 128).is_none() || !outside.exists());
    }
}
