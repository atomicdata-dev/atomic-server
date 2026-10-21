//! The device directory (pkarr, via n0's public relay) is shared by everyone,
//! so this device asks it as little as it can:
//! - the answer for a drive is kept for a while ([`LookupCache`]), and callers
//!   that ask for the same drive at the same time share one request: the
//!   search loop, `follow_listed_drives`, the needs-sync screen and the
//!   server lookup used to each go to the relay for the same drive;
//! - what the user asks for (Search again, pull to refresh, pairing) skips the
//!   kept answer ([`invalidate_all`], or `bypass`);
//! - every request that really leaves the device is counted, so a screen can
//!   say how many in the last hour ([`lookups_last_hour`]).

use atomic_lib::discovery::DriveRecord;
use futures::FutureExt;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

type Shared<T> = futures::future::Shared<futures::future::BoxFuture<'static, Result<T, String>>>;

enum Entry<T> {
    Fresh { at: Instant, value: T },
    InFlight(Shared<T>),
}

/// Answers per key with an age limit, and one request per key at a time.
/// Failures are never kept: the next caller asks again.
pub(crate) struct LookupCache<T> {
    entries: Arc<Mutex<HashMap<String, Entry<T>>>>,
}

impl<T: Clone + Send + Sync + 'static> LookupCache<T> {
    pub(crate) fn new() -> Self {
        LookupCache {
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The answer for `key`: kept if younger than `ttl` (unless `bypass`), the
    /// one already being fetched if there is one, else `fetch()`. The fetch
    /// runs on its own task, so a caller that gives up (a timeout) does not
    /// cancel it for the others.
    pub(crate) async fn get<F, Fut>(
        &self,
        key: &str,
        ttl: Duration,
        bypass: bool,
        fetch: F,
    ) -> Result<T, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, String>> + Send + 'static,
    {
        let shared = {
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            match entries.get(key) {
                Some(Entry::Fresh { at, value }) if !bypass && at.elapsed() < ttl => {
                    return Ok(value.clone());
                }
                Some(Entry::InFlight(shared)) => shared.clone(),
                _ => {
                    let (tx, rx) = futures::channel::oneshot::channel();
                    let shared: Shared<T> = rx
                        .map(|r| r.unwrap_or_else(|_| Err("lookup cancelled".to_string())))
                        .boxed()
                        .shared();
                    entries.insert(key.to_string(), Entry::InFlight(shared.clone()));
                    let fut = fetch();
                    let map = self.entries.clone();
                    let key = key.to_string();
                    tokio::spawn(async move {
                        let result = fut.await;
                        {
                            let mut entries = map.lock().unwrap_or_else(|e| e.into_inner());
                            match &result {
                                Ok(value) => {
                                    entries.insert(
                                        key,
                                        Entry::Fresh {
                                            at: Instant::now(),
                                            value: value.clone(),
                                        },
                                    );
                                }
                                Err(_) => {
                                    entries.remove(&key);
                                }
                            }
                        }
                        let _ = tx.send(result);
                    });
                    shared
                }
            }
        };
        shared.await
    }

    /// Forget every kept answer (a request under way finishes and is kept).
    pub(crate) fn invalidate_all(&self) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, e| matches!(e, Entry::InFlight(_)));
    }

    pub(crate) fn invalidate(&self, key: &str) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if matches!(entries.get(key), Some(Entry::Fresh { .. })) {
            entries.remove(key);
        }
    }
}

/// Requests that left the device, with their time.
static REQUESTS: LazyLock<Mutex<VecDeque<Instant>>> = LazyLock::new(|| Mutex::new(VecDeque::new()));
const HOUR: Duration = Duration::from_secs(3600);

pub(crate) fn note_request() {
    let mut requests = REQUESTS.lock().unwrap_or_else(|e| e.into_inner());
    requests.push_back(Instant::now());
    while requests.front().is_some_and(|t| t.elapsed() > HOUR) {
        requests.pop_front();
    }
}

/// How many directory requests this device made in the last hour.
pub(crate) fn lookups_last_hour() -> usize {
    let mut requests = REQUESTS.lock().unwrap_or_else(|e| e.into_inner());
    while requests.front().is_some_and(|t| t.elapsed() > HOUR) {
        requests.pop_front();
    }
    requests.len()
}

static RECORDS: LazyLock<LookupCache<DriveRecord>> = LazyLock::new(LookupCache::new);

/// How long the search loop trusts an answer: short, so the quick first
/// rounds still see a device that has just announced itself.
pub(crate) const SEARCH_TTL: Duration = Duration::from_secs(12);
/// How long everything else (followed drives, the server lookup) does.
pub(crate) const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// What the directory says about `drive`. `bypass` for what the user asked for.
pub(crate) async fn resolve_record(
    drive: &str,
    ttl: Duration,
    bypass: bool,
) -> Result<DriveRecord, String> {
    let subject = drive.to_string();
    RECORDS
        .get(drive, ttl, bypass, move || async move {
            note_request();
            atomic_lib::discovery::resolve_drive_record(&subject)
                .await
                .map_err(|e| e.to_string())
        })
        .await
}

/// The other devices the record names (never `exclude`, this device).
pub(crate) fn others(record: &DriveRecord, exclude: Option<&str>) -> Vec<String> {
    record
        .node_ids
        .iter()
        .filter(|id| Some(id.as_str()) != exclude)
        .cloned()
        .collect()
}

/// Announce this device for `drive` (a read and a write at the relay).
pub(crate) async fn announce(drive: &str, me: &str) -> Result<(), String> {
    note_request();
    let result = atomic_lib::discovery::publish_node_id(drive, me)
        .await
        .map_err(|e| e.to_string());
    RECORDS.invalidate(drive);
    result
}

/// The user asked: the next lookups go to the relay.
pub(crate) fn invalidate_all() {
    RECORDS.invalidate_all();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TTL: Duration = Duration::from_secs(60);

    fn counting(
        calls: &Arc<AtomicUsize>,
        delay_ms: u64,
        value: u32,
    ) -> impl FnOnce() -> futures::future::BoxFuture<'static, Result<u32, String>> {
        let calls = calls.clone();
        move || {
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                Ok(value)
            }
            .boxed()
        }
    }

    #[tokio::test]
    async fn concurrent_lookups_of_one_drive_share_one_request() {
        let cache = LookupCache::<u32>::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let results = futures::future::join_all(
            (0..8).map(|_| cache.get("d", TTL, false, counting(&calls, 50, 7))),
        )
        .await;
        assert!(results.iter().all(|r| r == &Ok(7)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_answer_is_kept_until_its_ttl_and_bypass_skips_it() {
        let cache = LookupCache::<u32>::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let ttl = Duration::from_millis(100);
        cache.get("d", ttl, false, counting(&calls, 0, 1)).await.unwrap();
        cache.get("d", ttl, false, counting(&calls, 0, 2)).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1, "kept");
        // Another drive is another request.
        cache.get("e", ttl, false, counting(&calls, 0, 3)).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        // The user asked: fresh.
        let v = cache.get("d", ttl, true, counting(&calls, 0, 4)).await.unwrap();
        assert_eq!((v, calls.load(Ordering::SeqCst)), (4, 3));
        // Invalidated: fresh.
        cache.invalidate_all();
        cache.get("d", ttl, false, counting(&calls, 0, 5)).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        // Older than the ttl: fresh.
        tokio::time::sleep(Duration::from_millis(120)).await;
        let v = cache.get("d", ttl, false, counting(&calls, 0, 6)).await.unwrap();
        assert_eq!((v, calls.load(Ordering::SeqCst)), (6, 5));
    }

    #[tokio::test]
    async fn a_failure_is_shared_but_not_kept() {
        let cache = LookupCache::<u32>::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let failing = |calls: &Arc<AtomicUsize>| {
            let calls = calls.clone();
            move || {
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Err::<u32, _>("relay unreachable".to_string())
                }
                .boxed()
            }
        };
        let (a, b) = tokio::join!(
            cache.get("d", TTL, false, failing(&calls)),
            cache.get("d", TTL, false, failing(&calls)),
        );
        assert!(a.is_err() && b.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Asked again: tries again.
        let v = cache.get("d", TTL, false, counting(&calls, 0, 9)).await;
        assert_eq!(v, Ok(9));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_caller_that_gives_up_does_not_cancel_the_request() {
        let cache = LookupCache::<u32>::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let timed_out = tokio::time::timeout(
            Duration::from_millis(10),
            cache.get("d", TTL, false, counting(&calls, 60, 8)),
        )
        .await;
        assert!(timed_out.is_err());
        // Another caller joins it, then it is kept.
        let v = cache.get("d", TTL, false, counting(&calls, 60, 9)).await;
        assert_eq!(v, Ok(8));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn requests_are_counted() {
        let before = lookups_last_hour();
        note_request();
        note_request();
        assert_eq!(lookups_last_hour(), before + 2);
    }

    #[test]
    fn others_leaves_out_this_device() {
        let record = DriveRecord {
            node_ids: vec!["a".into(), "b".into()],
            ..Default::default()
        };
        assert_eq!(others(&record, Some("a")), vec!["b".to_string()]);
        assert_eq!(others(&record, None).len(), 2);
    }
}
