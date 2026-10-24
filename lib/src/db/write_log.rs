//! A log of which subjects were written, and the cache the sync probe builds on it.
//!
//! A hash-first `SYNC` probe over a drive that did not change used to walk the
//! whole drive just to say "same hash". [`WriteLog`] sits at the KV choke point
//! ([`super::compressed_kv::CompressedKv`]) and records every write to a
//! resource row or snapshot as `(generation, subject)` in a bounded ring.
//! [`ProbeCache`] keeps the last hash per (drive, agent, wire, version) with the
//! generation it was computed at, and re-validates it against the writes since.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use super::trees::Tree;

const RING_CAP: usize = 4096;
const CACHE_CAP: usize = 128;

#[derive(Default)]
struct LogState {
    generation: u64,
    ring: VecDeque<(u64, String)>,
    /// Writes at or below this generation are no longer in the ring.
    floor: u64,
}

/// Monotonic write counter plus the last [`RING_CAP`] written subjects.
#[derive(Default)]
pub struct WriteLog {
    state: Mutex<LogState>,
}

/// The subject a `Tree::Resources` / `Tree::LoroSnapshots` key names, if a
/// write to it can change a drive's inventory. Commit rows never do.
pub(super) fn logged_subject(tree: Tree, key: &[u8]) -> Option<String> {
    if !matches!(tree, Tree::Resources | Tree::LoroSnapshots) {
        return None;
    }
    let key = std::str::from_utf8(key).ok()?;
    if key.starts_with(crate::identifiers::ATOMIC_COMMIT_PREFIX)
        || key.starts_with(crate::identifiers::DID_AD_COMMIT_PREFIX)
    {
        return None;
    }
    Some(key.to_string())
}

impl WriteLog {
    pub fn generation(&self) -> u64 {
        self.state.lock().map(|s| s.generation).unwrap_or(0)
    }

    /// Log writes that have already succeeded.
    pub fn record(&self, subjects: impl IntoIterator<Item = String>) {
        let Ok(mut s) = self.state.lock() else { return };
        for subject in subjects {
            s.generation += 1;
            let generation = s.generation;
            s.ring.push_back((generation, subject));
            if s.ring.len() > RING_CAP {
                if let Some((dropped, _)) = s.ring.pop_front() {
                    s.floor = dropped;
                }
            }
        }
    }

    /// A whole tree changed at once: nothing cached before this is trusted.
    pub fn invalidate_all(&self) {
        let Ok(mut s) = self.state.lock() else { return };
        s.generation += 1;
        s.floor = s.generation;
        s.ring.clear();
    }

    /// Subjects written after `generation`, or `None` if the ring no longer
    /// reaches back that far.
    fn since(&self, generation: u64) -> Option<(u64, Vec<String>)> {
        let s = self.state.lock().ok()?;
        if generation < s.floor {
            return None;
        }
        let written = s
            .ring
            .iter()
            .filter(|(g, _)| *g > generation)
            .map(|(_, subject)| subject.clone())
            .collect();
        Some((s.generation, written))
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ProbeKey {
    pub drive: String,
    pub agent: String,
    pub wire: crate::sync::engine::WireScheme,
    pub hash_version: u8,
}

struct ProbeEntry {
    generation: u64,
    hash: String,
    /// Every subject the walk found under the drive (readable or not).
    subjects: HashSet<String>,
    /// Subjects outside the drive that the read decision consulted: the
    /// drive root's ancestors and the `drive` stamps of its resources.
    externals: HashSet<String>,
}

#[derive(Default)]
struct Entries {
    map: HashMap<ProbeKey, ProbeEntry>,
    order: VecDeque<ProbeKey>,
}

#[derive(Default)]
pub struct ProbeCache {
    entries: Mutex<Entries>,
    hits: AtomicU64,
}

impl ProbeCache {
    /// How many probes were served without recomputing.
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            *entries = Entries::default();
        }
    }

    /// The cached hash if no write since it was computed can have changed it.
    /// A logged subject invalidates when it was in the drive (edited, moved
    /// out, destroyed, rights changed), was consulted for rights, or now has
    /// a parent inside the drive (new child, or a subtree moved in).
    pub fn lookup(
        &self,
        log: &WriteLog,
        key: &ProbeKey,
        parent_of: impl Fn(&str) -> Option<String>,
    ) -> Option<String> {
        let mut entries = self.entries.lock().ok()?;
        let entry = entries.map.get_mut(key)?;
        let (now, written) = log.since(entry.generation)?;
        for subject in &written {
            if entry.subjects.contains(subject) || entry.externals.contains(subject) {
                return None;
            }
            if parent_of(subject).is_some_and(|p| entry.subjects.contains(&p)) {
                return None;
            }
        }
        entry.generation = now;
        self.hits.fetch_add(1, Ordering::Relaxed);
        Some(entry.hash.clone())
    }

    /// Remember `hash`, computed from reads made after `generation` was read.
    pub fn store(
        &self,
        key: ProbeKey,
        generation: u64,
        hash: String,
        subjects: HashSet<String>,
        externals: HashSet<String>,
    ) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if entries.map.remove(&key).is_some() {
            entries.order.retain(|k| k != &key);
        }
        while entries.map.len() >= CACHE_CAP {
            match entries.order.pop_front() {
                Some(oldest) => {
                    entries.map.remove(&oldest);
                }
                None => break,
            }
        }
        entries.order.push_back(key.clone());
        entries.map.insert(
            key,
            ProbeEntry {
                generation,
                hash,
                subjects,
                externals,
            },
        );
    }
}

/// The probe-hash cache (`db::write_log`): a repeat probe of an unchanged
/// drive is served from the cache, and every kind of write that could change
/// the answer invalidates it.
#[cfg(test)]
mod tests {
    use crate::db::trees::{Method, Operation, Tree};
    use crate::sync::engine::{drive_sync_hash_for_wire_version, WireScheme};
    use crate::{agents::ForAgent, urls, Db, Storelike, Value};

    async fn probe(db: &Db, drive: &str, agent: &ForAgent) -> Result<String, String> {
        drive_sync_hash_for_wire_version(db, drive, agent, WireScheme::CANONICAL, 2).await
    }

    /// A probe through a brand-new `ProbeCache` state: the ground truth.
    async fn fresh(db: &Db, drive: &str) -> String {
        db.probe_cache().clear();
        probe(db, drive, &ForAgent::Sudo).await.unwrap()
    }

    async fn child(db: &Db, parent: &str, name: &str) -> String {
        let props = vec![
            (urls::DESCRIPTION, Value::Markdown("x".into())),
            (urls::SHORTNAME, Value::Slug(name.into())),
        ];
        db.create_resource(urls::CLASS, parent, name, Some(props))
            .await
            .unwrap()
    }

    async fn edit(db: &Db, subject: &str, text: &str) {
        let mut r = db.get_resource(&subject.into()).await.unwrap();
        r.set(urls::DESCRIPTION.into(), Value::Markdown(text.into()), db)
            .await
            .unwrap();
        r.save_locally(db).await.unwrap();
    }

    async fn reparent(db: &Db, subject: &str, parent: &str) {
        let mut r = db.get_resource(&subject.into()).await.unwrap();
        r.set(urls::PARENT.into(), Value::AtomicUrl(parent.into()), db)
            .await
            .unwrap();
        r.save_locally(db).await.unwrap();
    }

    /// Probe with the cache warm, assert the hash equals a cold computation.
    async fn warm(db: &Db, drive: &str) -> String {
        let hash = probe(db, drive, &ForAgent::Sudo).await.unwrap();
        assert_eq!(hash, fresh(db, drive).await);
        probe(db, drive, &ForAgent::Sudo).await.unwrap()
    }

    #[tokio::test]
    async fn unchanged_drive_is_served_from_cache() {
        let db = Db::init_temp("probe_cache_hit").await.unwrap();
        let (_a, drive) = db.setup("Alice").await.unwrap();
        child(&db, &drive, "one").await;
        let first = probe(&db, &drive, &ForAgent::Sudo).await.unwrap();
        let hits = db.probe_cache().hits();
        assert_eq!(probe(&db, &drive, &ForAgent::Sudo).await.unwrap(), first);
        assert_eq!(db.probe_cache().hits(), hits + 1);
        assert_eq!(fresh(&db, &drive).await, first);
    }

    #[tokio::test]
    async fn editing_a_resource_invalidates() {
        let db = Db::init_temp("probe_cache_edit").await.unwrap();
        let (_a, drive) = db.setup("Alice").await.unwrap();
        let doc = child(&db, &drive, "one").await;
        let before = warm(&db, &drive).await;
        edit(&db, &doc, "changed").await;
        let after = probe(&db, &drive, &ForAgent::Sudo).await.unwrap();
        assert_ne!(before, after);
        assert_eq!(after, fresh(&db, &drive).await);
    }

    #[tokio::test]
    async fn a_new_child_invalidates() {
        let db = Db::init_temp("probe_cache_child").await.unwrap();
        let (_a, drive) = db.setup("Alice").await.unwrap();
        let folder = child(&db, &drive, "folder").await;
        let before = warm(&db, &drive).await;
        child(&db, &folder, "nested").await;
        let after = probe(&db, &drive, &ForAgent::Sudo).await.unwrap();
        assert_ne!(before, after);
        assert_eq!(after, fresh(&db, &drive).await);
    }

    #[tokio::test]
    async fn moving_out_and_in_invalidates() {
        let db = Db::init_temp("probe_cache_move").await.unwrap();
        let (_a, drive) = db.setup("Alice").await.unwrap();
        let other = db.create_drive("Other").await.unwrap();
        let doc = child(&db, &drive, "mover").await;
        let before = warm(&db, &drive).await;
        reparent(&db, &doc, &other).await;
        let out = probe(&db, &drive, &ForAgent::Sudo).await.unwrap();
        assert_ne!(before, out);
        assert_eq!(out, fresh(&db, &drive).await);

        // And back in: the moved resource's parent is now in the drive.
        let before_in = warm(&db, &drive).await;
        reparent(&db, &doc, &drive).await;
        let back = probe(&db, &drive, &ForAgent::Sudo).await.unwrap();
        assert_ne!(before_in, back);
        assert_eq!(back, fresh(&db, &drive).await);
    }

    #[tokio::test]
    async fn a_write_in_another_drive_keeps_the_entry() {
        let db = Db::init_temp("probe_cache_other").await.unwrap();
        let (_a, drive) = db.setup("Alice").await.unwrap();
        let other = db.create_drive("Other").await.unwrap();
        child(&db, &drive, "mine").await;
        let theirs = child(&db, &other, "theirs").await;
        let before = warm(&db, &drive).await;
        let hits = db.probe_cache().hits();
        edit(&db, &theirs, "elsewhere").await;
        child(&db, &other, "more").await;
        assert_eq!(probe(&db, &drive, &ForAgent::Sudo).await.unwrap(), before);
        assert_eq!(db.probe_cache().hits(), hits + 1, "served from cache");
        assert_eq!(fresh(&db, &drive).await, before);
    }

    #[tokio::test]
    async fn ring_overflow_forces_a_recompute() {
        let db = Db::init_temp("probe_cache_overflow").await.unwrap();
        let (_a, drive) = db.setup("Alice").await.unwrap();
        warm(&db, &drive).await;
        let hits = db.probe_cache().hits();
        // Unrelated writes, more than the ring holds.
        db.write_log()
            .record((0..5000).map(|i| format!("did:ad:unrelated{i}")));
        probe(&db, &drive, &ForAgent::Sudo).await.unwrap();
        assert_eq!(db.probe_cache().hits(), hits, "recomputed, not served");
        // The recompute re-stored it, so the next one is a hit again.
        probe(&db, &drive, &ForAgent::Sudo).await.unwrap();
        assert_eq!(db.probe_cache().hits(), hits + 1);
    }

    #[tokio::test]
    async fn clearing_a_tree_forces_a_recompute() {
        let db = Db::init_temp("probe_cache_clear").await.unwrap();
        let (_a, drive) = db.setup("Alice").await.unwrap();
        warm(&db, &drive).await;
        let hits = db.probe_cache().hits();
        db.kv.clear_tree(Tree::LoroSnapshots).unwrap();
        let _ = probe(&db, &drive, &ForAgent::Sudo).await;
        assert_eq!(db.probe_cache().hits(), hits);
    }

    #[tokio::test]
    async fn a_batch_counts_only_after_commit() {
        let db = Db::init_temp("probe_cache_batch").await.unwrap();
        let (_a, drive) = db.setup("Alice").await.unwrap();
        warm(&db, &drive).await;
        let generation = db.write_log().generation();
        db.kv.begin_batch();
        db.kv
            .insert(Tree::Resources, drive.as_bytes(), b"{}")
            .unwrap();
        db.kv
            .apply_batch(&[Operation {
                tree: Tree::LoroSnapshots,
                method: Method::Delete,
                key: drive.as_bytes().to_vec(),
                val: None,
            }])
            .unwrap();
        assert_eq!(db.write_log().generation(), generation, "buffered");
        db.kv.commit_batch().unwrap();
        assert!(db.write_log().generation() > generation, "logged on commit");
        let hits = db.probe_cache().hits();
        let _ = probe(&db, &drive, &ForAgent::Sudo).await;
        assert_eq!(db.probe_cache().hits(), hits, "the drive was written");
    }

    #[tokio::test]
    async fn agents_get_separate_entries() {
        let db = Db::init_temp("probe_cache_agents").await.unwrap();
        let (alice, drive) = db.setup("Alice").await.unwrap();
        child(&db, &drive, "secret").await;
        let owner = ForAgent::AgentSubject(alice.subject.clone());
        let as_owner = probe(&db, &drive, &owner).await.unwrap();
        assert_eq!(probe(&db, &drive, &owner).await.unwrap(), as_owner);
        // A cached owner entry must not answer for Public or a stranger.
        assert!(probe(&db, &drive, &ForAgent::Public).await.is_err());
        let mallory = db.create_agent(Some("Mallory")).await.unwrap();
        let stranger = ForAgent::AgentSubject(mallory.subject.clone());
        assert!(probe(&db, &drive, &stranger).await.is_err());
        assert_eq!(probe(&db, &drive, &owner).await.unwrap(), as_owner);
    }
}
