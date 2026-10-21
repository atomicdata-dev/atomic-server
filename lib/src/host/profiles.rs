//! Agents this device does not hold: their profile (JSON-AD) as the connected
//! server has it, fetched through the host's [`AgentProfileFetcher`] and kept
//! in memory.
//!
//! The embedded web page cannot fetch from a server (its store does not
//! connect), and the native lists need the same names, so both read through
//! one [`AgentProfiles`] cache.
//!
//! A fetched profile is **not** written to the store. It is data a server
//! handed us, not something this device signed or verified, and the store
//! holds what the device can vouch for. It lives only in this cache, for the
//! life of the process, and is only ever shown (name, avatar). Failures are
//! remembered for a while so a slow or offline server is not asked on every
//! read.

use super::AgentProfileFetcher;
use futures::{future::BoxFuture, FutureExt};
use serde_json::Value as Json;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// How long one lookup may take before it counts as failed.
pub const PROFILE_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a failed lookup is not repeated.
pub const PROFILE_RETRY: Duration = Duration::from_secs(60);

type Lookup = futures::future::Shared<BoxFuture<'static, Option<String>>>;

enum Entry {
    Found(String),
    Failed(Instant),
    Pending(Lookup),
}

struct Inner {
    fetcher: Arc<dyn AgentProfileFetcher>,
    entries: Mutex<HashMap<String, Entry>>,
    timeout: Duration,
    retry: Duration,
}

/// The shared, in-memory cache of fetched agent profiles. Cheap to clone.
#[derive(Clone)]
pub struct AgentProfiles(Arc<Inner>);

/// What the cache holds for one agent right now.
enum State {
    Found(String),
    Failed,
    Pending(Lookup),
}

impl AgentProfiles {
    pub fn new(fetcher: Arc<dyn AgentProfileFetcher>) -> Self {
        Self::with_timing(fetcher, PROFILE_TIMEOUT, PROFILE_RETRY)
    }

    /// A cache that knows no profiles.
    pub fn none() -> Self {
        Self::new(Arc::new(super::NoProfiles))
    }

    /// Like [`new`](Self::new), with other timeouts (for tests).
    pub fn with_timing(
        fetcher: Arc<dyn AgentProfileFetcher>,
        timeout: Duration,
        retry: Duration,
    ) -> Self {
        Self(Arc::new(Inner {
            fetcher,
            entries: Default::default(),
            timeout,
            retry,
        }))
    }

    /// The state of `agent`, starting a lookup (in its own task, so it
    /// finishes even when nobody waits for it) unless one is cached, running
    /// or failed recently.
    fn state(&self, agent: &str) -> State {
        let mut entries = self.0.entries.lock().expect("profile cache poisoned");
        match entries.get(agent) {
            Some(Entry::Found(json)) => return State::Found(json.clone()),
            Some(Entry::Pending(lookup)) => return State::Pending(lookup.clone()),
            Some(Entry::Failed(at)) if at.elapsed() < self.0.retry => return State::Failed,
            _ => {}
        }
        let inner = self.0.clone();
        let subject = agent.to_string();
        let task = tokio::spawn(async move {
            let fetched =
                tokio::time::timeout(inner.timeout, inner.fetcher.fetch_agent_resource(&subject))
                    .await
                    .ok()
                    .flatten()
                    .and_then(|body| as_profile(&subject, &body));
            let mut entries = inner.entries.lock().expect("profile cache poisoned");
            match &fetched {
                Some(json) => entries.insert(subject, Entry::Found(json.clone())),
                None => entries.insert(subject, Entry::Failed(Instant::now())),
            };
            fetched
        });
        let lookup: Lookup = async move { task.await.ok().flatten() }.boxed().shared();
        entries.insert(agent.to_string(), Entry::Pending(lookup.clone()));
        State::Pending(lookup)
    }

    /// The profile of `agent` as JSON-AD (under the id it was asked by). Waits
    /// for a lookup, but never longer than the cache's timeout; `None` when
    /// it is not found (now).
    pub async fn get(&self, agent: &str) -> Option<String> {
        match self.state(agent) {
            State::Found(json) => Some(json),
            State::Failed => None,
            State::Pending(lookup) => lookup.await,
        }
    }

    /// The cached profile, never waiting: when it is not cached a lookup
    /// starts in the background and this is `None`, so a later call has it.
    fn cached_or_prefetch(&self, agent: &str) -> Option<String> {
        match self.state(agent) {
            State::Found(json) => Some(json),
            State::Failed | State::Pending(_) => None,
        }
    }

    /// The display name of a profile, as [`cached_or_prefetch`](Self::cached_or_prefetch).
    pub fn name_or_prefetch(&self, agent: &str) -> Option<String> {
        self.cached_or_prefetch(agent)
            .and_then(|json| super::conversations::name_from_json_ad(&json))
    }
}

/// The public key an agent subject names, in one spelling: `atomic:agent:K`,
/// `did:ad:agent:K` and the legacy `https://host/agents/K` /
/// `internal:/agents/K` all give the same key, as do the standard and the
/// URL-safe base64 alphabet (with or without padding). `None` when the
/// subject names no agent.
pub fn agent_key(subject: &str) -> Option<String> {
    let migrated =
        crate::agents::migrate_legacy_agent_subject(subject.trim().trim_end_matches('/'));
    let key = crate::identifiers::agent_public_key(&migrated)?;
    let key: String = key
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    (!key.is_empty()).then_some(key)
}

/// Whether two subjects name the same agent, whatever their spelling (see
/// [`agent_key`]). Subjects that name no agent compare as strings.
pub fn same_agent(a: &str, b: &str) -> bool {
    match (agent_key(a), agent_key(b)) {
        (Some(a), Some(b)) => a == b,
        (None, None) => a == b,
        _ => false,
    }
}

/// What to call an agent whose name is not known: the start of its key
/// (`a3f9…`), so two unknown members still look different.
pub fn short_agent(subject: &str) -> String {
    let key = agent_key(subject).unwrap_or_else(|| {
        subject
            .trim_end_matches('/')
            .rsplit(['/', ':'])
            .next()
            .unwrap_or_default()
            .to_string()
    });
    let start: String = key.chars().take(4).collect();
    if start.is_empty() {
        "Unknown member".into()
    } else {
        format!("{start}…")
    }
}

/// A fetched body as one JSON-AD object whose `@id` is the subject it was
/// asked by (the server may answer under its own URL). `None` when it is not
/// a resource.
fn as_profile(asked: &str, body: &str) -> Option<String> {
    let json: Json = serde_json::from_str(body).ok()?;
    let mut resource = match json {
        Json::Array(mut items) if !items.is_empty() => items.swap_remove(0),
        other => other,
    };
    let object = resource.as_object_mut()?;
    object.insert("@id".into(), Json::String(asked.to_string()));
    Some(resource.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::urls;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Answers `reply` and counts the calls.
    struct Fake {
        reply: Option<String>,
        calls: AtomicUsize,
    }

    impl Fake {
        fn new(reply: Option<String>) -> Arc<Self> {
            Arc::new(Self {
                reply,
                calls: AtomicUsize::new(0),
            })
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl AgentProfileFetcher for Fake {
        async fn fetch_agent_resource(&self, _agent: &str) -> Option<String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.reply.clone()
        }
    }

    fn ada() -> String {
        format!(
            r#"{{"@id":"https://server.test/x","{}":"Ada"}}"#,
            urls::NAME
        )
    }

    #[tokio::test]
    async fn a_profile_is_fetched_once_and_cached() {
        let fake = Fake::new(Some(ada()));
        let profiles = AgentProfiles::new(fake.clone());
        let json = profiles.get("atomic:agent:abc").await.unwrap();
        assert!(json.contains("Ada"));
        assert!(json.contains(r#""@id":"atomic:agent:abc""#), "{json}");
        assert_eq!(profiles.get("atomic:agent:abc").await.unwrap(), json);
        assert_eq!(
            profiles.name_or_prefetch("atomic:agent:abc").as_deref(),
            Some("Ada")
        );
        assert_eq!(fake.calls(), 1);
    }

    #[tokio::test]
    async fn concurrent_reads_share_one_lookup() {
        let fake = Fake::new(Some(ada()));
        let profiles = AgentProfiles::new(fake.clone());
        let (a, b) = tokio::join!(
            profiles.get("atomic:agent:abc"),
            profiles.get("atomic:agent:abc")
        );
        assert_eq!(a, b);
        assert!(a.is_some());
        assert_eq!(fake.calls(), 1);
    }

    #[tokio::test]
    async fn a_failure_is_not_retried_until_the_retry_window_passes() {
        let fake = Fake::new(None);
        let profiles =
            AgentProfiles::with_timing(fake.clone(), PROFILE_TIMEOUT, Duration::from_millis(150));
        assert_eq!(profiles.get("atomic:agent:abc").await, None);
        assert_eq!(profiles.get("atomic:agent:abc").await, None);
        assert_eq!(fake.calls(), 1);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(profiles.get("atomic:agent:abc").await, None);
        assert_eq!(fake.calls(), 2);
    }

    struct Hangs;

    #[async_trait::async_trait]
    impl AgentProfileFetcher for Hangs {
        async fn fetch_agent_resource(&self, _agent: &str) -> Option<String> {
            tokio::time::sleep(Duration::from_secs(30)).await;
            None
        }
    }

    #[tokio::test]
    async fn a_hanging_server_does_not_block_past_the_timeout() {
        let profiles =
            AgentProfiles::with_timing(Arc::new(Hangs), Duration::from_millis(50), PROFILE_RETRY);
        let started = Instant::now();
        assert_eq!(profiles.get("atomic:agent:abc").await, None);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn one_agent_in_every_spelling_is_the_same_agent() {
        let key = "RqPwpgHv+PK7Pnz/dVab8hmHjYnvTL1YrlVa6L9G9Zg=";
        let url_safe = "RqPwpgHv-PK7Pnz_dVab8hmHjYnvTL1YrlVa6L9G9Zg";
        let spellings = [
            format!("atomic:agent:{key}"),
            format!("did:ad:agent:{key}"),
            format!("did:ad:agent:{url_safe}"),
            format!("https://example.test/agents/{key}"),
            format!("internal:/agents/{key}"),
        ];
        for a in &spellings {
            for b in &spellings {
                assert!(same_agent(a, b), "{a} vs {b}");
            }
        }
        assert!(!same_agent(&spellings[0], "did:ad:agent:someoneelse"));
        assert!(!same_agent(&spellings[0], "did:ad:somedocument"));
        assert_eq!(short_agent(&spellings[1]), "RqPw…");
        assert_eq!(short_agent(""), "Unknown member");
    }

    #[tokio::test]
    async fn something_that_is_not_a_resource_counts_as_not_found() {
        let profiles = AgentProfiles::new(Fake::new(Some("<html>".into())));
        assert_eq!(profiles.get("atomic:agent:abc").await, None);
    }
}
