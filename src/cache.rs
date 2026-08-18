//! The optional two-layer cache, and why it has two layers.
//!
//! A "content hashes only" cache is unimplementable: a range response or a checkpoint has no
//! digest known before it is fetched, so there is nothing to look it up by. The cache is
//! therefore split:
//!
//! * an **object store**, keyed by the digest of the stored bytes;
//! * an **untrusted request index**, mapping a request key to a digest.
//!
//! The request key binds the **locally selected checkpoint identity**
//! `{log_id, tree_size, root_hash}`, not merely endpoint and range. After an equivocation two
//! distinct roots exist at one `tree_size`, so a key built from endpoint + range + size would
//! serve material from the wrong branch — see [`request_key`].
//!
//! The index has **zero evidentiary weight**. Every object is re-verified from its bytes on
//! read exactly as if it had just arrived: this layer recomputes the digest and evicts on
//! mismatch, and the caller then re-runs the same proof checks it would have run on a fresh
//! response, against the **locally selected** root — never against a checkpoint carried inside
//! the cached response. A poisoned index can therefore change *what work happens*, never *what
//! is accepted*.
//!
//! Consequences that follow, and are tested:
//!
//! * a request for the *latest* checkpoint is never served from cache (a valid old checkpoint
//!   is a replay) — expressed by such requests carrying no `cache_key` at all;
//! * a cached object failing re-verification is evicted and refetched once, then reported;
//! * the store is bounded by a byte quota and evicts least-recently-used, so a long
//!   enumeration cannot fill the disk.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use ahl_core::sha256_hex;

use crate::error::{CliError, CliResult};
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
    objects: PathBuf,
    index: PathBuf,
    quota_bytes: u64,
}

impl Cache {
    /// Open (creating if needed) a cache under `dir`, bounded by `quota_bytes`.
    ///
    /// # Errors
    ///
    /// [`CliError::Output`] if the directories cannot be created.
    pub fn open(dir: &Path, quota_bytes: u64) -> CliResult<Self> {
        let objects = dir.join("objects");
        let index = dir.join("index");
        for path in [&objects, &index] {
            std::fs::create_dir_all(path).map_err(|source| CliError::Output {
                path: path.display().to_string(),
                detail: source.to_string(),
            })?;
        }
        Ok(Self { objects, index, quota_bytes })
    }

    fn index_path(&self, key: &str) -> PathBuf {
        self.index.join(sanitize(key))
    }

    fn object_path(&self, digest: &str) -> PathBuf {
        self.objects.join(sanitize(digest))
    }

    /// Look up `key`, re-verifying the stored bytes against their own digest.
    ///
    /// A stored object whose bytes no longer hash to the digest they are filed under is
    /// evicted here and reported as a miss, so the caller refetches.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let digest = std::fs::read_to_string(self.index_path(key)).ok()?;
        let digest = digest.trim().to_owned();
        let object = self.object_path(&digest);
        let bytes = std::fs::read(&object).ok()?;
        if sha256_hex(&bytes) == digest {
            // Touch for the LRU. A failure here only costs eviction accuracy.
            let _ = filetime_touch(&object);
            Some(bytes)
        } else {
            let _ = std::fs::remove_file(&object);
            let _ = std::fs::remove_file(self.index_path(key));
            None
        }
    }

    /// Store `bytes` under `key`, then enforce the byte quota.
    ///
    /// # Errors
    ///
    /// [`CliError::Output`] if the object or index entry cannot be written.
    pub fn put(&self, key: &str, bytes: &[u8]) -> CliResult<()> {
        let digest = sha256_hex(bytes);
        let object = self.object_path(&digest);
        if !object.exists() {
            write_atomic(&object, bytes)?;
        }
        write_atomic(&self.index_path(key), digest.as_bytes())?;
        self.enforce_quota();
        Ok(())
    }

    /// Remove the index entry and its object.
    pub fn evict(&self, key: &str) {
        if let Ok(digest) = std::fs::read_to_string(self.index_path(key)) {
            let _ = std::fs::remove_file(self.object_path(digest.trim()));
        }
        let _ = std::fs::remove_file(self.index_path(key));
    }

    /// Total bytes currently held in the object store.
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        entries(&self.objects).iter().map(|(_, size, _)| *size).sum()
    }

    /// Drop least-recently-used objects until the store is within quota.
    fn enforce_quota(&self) {
        let mut objects = entries(&self.objects);
        let mut total: u64 = objects.iter().map(|(_, size, _)| *size).sum();
        if total <= self.quota_bytes {
            return;
        }
        objects.sort_by_key(|(_, _, accessed)| *accessed);
        for (path, size, _) in objects {
            if total <= self.quota_bytes {
                break;
            }
            if std::fs::remove_file(&path).is_ok() {
                total = total.saturating_sub(size);
            }
        }
    }
}

fn sanitize(key: &str) -> String {
    key.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect()
}

fn entries(dir: &Path) -> Vec<(PathBuf, u64, SystemTime)> {
    let Ok(read) = std::fs::read_dir(dir) else { return Vec::new() };
    read.filter_map(|entry| {
        let entry = entry.ok()?;
        let metadata = entry.metadata().ok()?;
        let accessed = metadata.accessed().or_else(|_| metadata.modified()).ok()?;
        Some((entry.path(), metadata.len(), accessed))
    })
    .collect()
}

/// Re-write a file so its access time advances, which is what the LRU orders on.
fn filetime_touch(path: &Path) -> std::io::Result<()> {
    let bytes = std::fs::read(path)?;
    std::fs::write(path, bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> CliResult<()> {
    // Cache files are this process's own bookkeeping, so the no-replace install of
    // `crate::install` is deliberately not used here: overwriting a cache entry is the normal
    // case, and a cache entry has no evidentiary weight to protect.
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, bytes).map_err(|source| CliError::Output {
        path: temporary.display().to_string(),
        detail: source.to_string(),
    })?;
    std::fs::rename(&temporary, path).map_err(|source| CliError::Output {
        path: path.display().to_string(),
        detail: source.to_string(),
    })
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
            // A cached object is returned with the status a successful fetch carries; the
            // caller re-runs every proof check against the locally selected root regardless,
            // so this cannot decide what is accepted.
            return Ok(Response { status: 200, body: bytes });
        }
        let response = self.inner.fetch(request)?;
        if response.status == 200 {
            // A cache write failure is not a verification failure: the operation continues
            // with the bytes it already has.
            let _ = self.cache.put(key, &response.body);
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        calls: std::sync::atomic::AtomicUsize,
    }

    impl Counting {
        fn new(body: &[u8]) -> Self {
            Self { body: body.to_vec(), calls: std::sync::atomic::AtomicUsize::new(0) }
        }
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl Fetcher for Counting {
        fn fetch(&self, _request: &Request) -> Result<Response, FetchFailure> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(Response { status: 200, body: self.body.clone() })
        }
    }

    #[test]
    fn the_request_key_binds_the_selected_checkpoint_identity() {
        let request = Request::post("https://m/v1/range", b"{\"from\":0}".to_vec());
        let branch_a = request_key(&identity(&"aa".repeat(32)), &request);
        let branch_b = request_key(&identity(&"bb".repeat(32)), &request);
        assert_ne!(
            branch_a, branch_b,
            "two roots at one tree_size must not share a cache entry"
        );

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

        assert_eq!(caching.fetch(&request).expect("cold").body, b"payload");
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
    }

    #[test]
    fn a_poisoned_object_is_evicted_and_refetched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(dir.path(), 1 << 20).expect("open cache");
        let caching = Caching::new(Counting::new(b"payload"), cache);
        let request = Request::get("https://m/v1/x").cached_under("k1");
        let _ = caching.fetch(&request).expect("cold");

        // Overwrite every stored object with attacker bytes, leaving the index intact.
        for (path, _, _) in entries(&caching.cache.objects) {
            std::fs::write(&path, b"attacker").expect("poison");
        }
        assert!(caching.cache.get("k1").is_none(), "a poisoned object must not be served");

        let response = caching.fetch(&request).expect("refetch");
        assert_eq!(response.body, b"payload");
        assert_eq!(caching.inner.calls(), 2, "the poisoned entry must have been refetched");
    }

    #[test]
    fn a_poisoned_index_pointing_at_nothing_is_a_miss_not_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(dir.path(), 1 << 20).expect("open cache");
        std::fs::write(cache.index_path("k1"), format!("sha256:{}", "ff".repeat(32)))
            .expect("write index");
        assert!(cache.get("k1").is_none());
    }

    #[test]
    fn eviction_removes_an_entry_and_its_object() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(dir.path(), 1 << 20).expect("open cache");
        cache.put("k1", b"payload").expect("put");
        assert!(cache.get("k1").is_some());
        cache.evict("k1");
        assert!(cache.get("k1").is_none());
        assert_eq!(cache.size_bytes(), 0);
        // Evicting an absent key is a no-op, not a failure.
        cache.evict("k1");
    }

    #[test]
    fn the_byte_quota_bounds_the_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(dir.path(), 300).expect("open cache");
        for n in 0u8..10 {
            cache.put(&format!("k{n}"), &vec![n; 100]).expect("put");
        }
        assert!(
            cache.size_bytes() <= 300,
            "quota exceeded: {} bytes held",
            cache.size_bytes()
        );
    }

    #[test]
    fn identical_bytes_under_two_keys_share_one_object() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(dir.path(), 1 << 20).expect("open cache");
        cache.put("k1", b"same").expect("put");
        cache.put("k2", b"same").expect("put");
        assert_eq!(entries(&cache.objects).len(), 1);
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
        assert_eq!(caching.fetch(&request).expect("404").status, 404);
        assert!(caching.cache().get("k1").is_none());
    }

    #[test]
    fn opening_a_cache_under_an_unusable_directory_is_an_output_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").expect("write");
        assert!(Cache::open(&file, 1 << 20).is_err());
    }
}
