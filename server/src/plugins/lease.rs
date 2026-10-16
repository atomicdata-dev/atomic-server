//! Who runs an Installation's background work when several nodes sync a drive.
//!
//! A *lease* is an ordinary resource (`Lease`, `lib/defaults/plugins.json`)
//! under the Installation: the holder node, an expiry, a generation and the
//! lease it took over. It is created and renewed with normal signed commits, so
//! it syncs like anything else. Triggers and schedules
//! ([`super::triggers`], [`super::scheduler`]) run on a node only while
//! [`Leases::holds`] says it holds an unexpired lease.
//!
//! # Protocol
//!
//! - **First lease.** No lease exists: write one (generation 0, no previous).
//! - **Renew.** The holder rewrites `leaseExpiresAt` of its own lease before
//!   it runs out ([`RENEW_BEFORE_MS`]). Only the holder ever writes a lease
//!   after creating it, so renewals never conflict with each other.
//! - **Take over.** A node that sees the head lease held by someone else and
//!   expired writes a *new* lease: `previousLease` = the head, generation = the
//!   head's plus one.
//!
//! # Which leases count
//!
//! Leases are found by the `leaseOf` index across the whole store, so a lease
//! counts only when it is a *child of the Installation* (which keeps it in the
//! Installation's drive), its genesis was signed by an agent that may write the
//! Installation (this node's own agent always may; a peer node's agent must be
//! granted write like any other), and its generation is one a protocol
//! follower could have reached by now (a takeover needs the previous lease to
//! have run out, so at most one per [`TTL_MS`]). Leases more than one takeover
//! behind the head are removed by the node that holds.
//!
//! # Who is the holder (convergence)
//!
//! The head is the maximum of the leases a node has over the total order
//! `(generation high first, holder node id low first, subject low first)`.
//! `generation`, `leaseHolder` and the subject never change after a lease is
//! created (the subject is the hash of its genesis signature), and the order
//! is total, so the maximum of a set does not depend on the order the members
//! arrived in. Two nodes holding the same set of leases therefore pick the same
//! head, and sets only grow towards the union. Concurrent takeovers write the
//! same generation, so the lowest node id wins; a concurrent *first* lease is
//! the same case. Expiry never takes part in picking the head, only in whether
//! the head may be replaced, so a late-synced renewal cannot flip the outcome.
//!
//! Until the leases have synced, both contenders run (the window is the sync
//! latency); afterwards the loser sees a head that is not itself and stops.
//! A node that was the holder keeps running until its cached verdict runs out
//! at the next renewal point at the latest, so the overlap after losing is
//! bounded by [`RENEW_BEFORE_MS`] plus sync latency.
//!
//! Clocks: expiry is compared with each node's own clock, so nodes should agree
//! to within a fraction of [`TTL_MS`]. Skew shortens or lengthens a lease; it
//! cannot make two nodes disagree about the head.
//!
//! # Delivery across a takeover: at-least-once
//!
//! Cursors (`event-ck`, `trigger/<plugin>`) and in-flight records are not part
//! of the lease; they stay in each node's db. The new holder resumes from the
//! cursor it has. A node that was not the holder did not move its cursor, so it
//! may repeat edges the old holder already handled: delivery is at-least-once,
//! and a consumer must tolerate a repeat. The edges that can repeat are those
//! the old holder handled since the new holder last held the lease (up to the
//! 7-day retention of the stream). Nothing is lost: an edge the old holder
//! had not yet handled is in the new holder's own stream too, because every
//! node writes the event row for each commit it applies.
//!
//! With a single node (no Iroh node id, or no known peer for the drive and no
//! lease ever synced) [`Leases::holds`] is a map lookup and writes nothing.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use atomic_lib::{
    agents::ForAgent,
    hierarchy::check_write,
    identifiers::{canonicalize_scheme, commit_subject, identifier_body},
    storelike::Query,
    sync::peer,
    urls, Db, Resource, Storelike, Value,
};

/// How long a lease lasts after it is written or renewed.
pub const TTL_MS: i64 = 60_000;
/// The holder renews once less than this is left.
pub const RENEW_BEFORE_MS: i64 = 30_000;
/// How long a node that is alone waits before looking again.
const SOLO_RECHECK_MS: i64 = 10_000;

/// Time, injectable so tests do not sleep.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> i64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        atomic_lib::utils::now()
    }
}

/// A lease as read from its resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub subject: String,
    pub holder: String,
    pub expires_at: i64,
    pub generation: i64,
    pub previous: Option<String>,
}

impl Lease {
    pub(crate) fn read(resource: &Resource) -> Option<Self> {
        Some(Self {
            subject: resource.get_subject().to_string(),
            holder: resource.get(urls::LEASE_HOLDER).ok()?.to_string(),
            expires_at: resource.get(urls::LEASE_EXPIRES_AT).ok()?.to_int().ok()?,
            generation: resource.get(urls::LEASE_GENERATION).ok()?.to_int().ok()?,
            previous: resource
                .get(urls::PREVIOUS_LEASE)
                .ok()
                .map(|v| v.to_string()),
        })
    }

    /// Sorts the better head first: higher generation, then lower node id,
    /// then lower subject.
    fn rank(&self, other: &Self) -> std::cmp::Ordering {
        other
            .generation
            .cmp(&self.generation)
            .then_with(|| self.holder.cmp(&other.holder))
            .then_with(|| self.subject.cmp(&other.subject))
    }
}

/// The lease that counts: the maximum of the set under the total order, so it
/// does not depend on the order the leases arrived in.
pub fn head(leases: impl IntoIterator<Item = Lease>) -> Option<Lease> {
    leases.into_iter().min_by(|a, b| a.rank(b))
}

enum Identity {
    /// The node's Iroh id, once Iroh has started.
    Node,
    Fixed(String),
}

/// What this node last decided for one Installation.
struct Verdict {
    /// Until when the verdict stands without looking at the db again.
    until: i64,
}

pub struct Leases {
    clock: Arc<dyn Clock>,
    identity: Identity,
    held: Mutex<HashMap<(String, String), Verdict>>,
    /// The commits this node wrote, for a test to carry to another node.
    #[cfg(test)]
    pub sent: Mutex<Vec<atomic_lib::commit::Commit>>,
}

impl Leases {
    pub fn system() -> Self {
        Self {
            clock: Arc::new(SystemClock),
            identity: Identity::Node,
            held: Mutex::default(),
            #[cfg(test)]
            sent: Mutex::default(),
        }
    }

    /// A node with a chosen id and clock, for tests that run several in one
    /// process.
    pub fn with(node: &str, clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            identity: Identity::Fixed(peer::normalize_node_id(node)),
            held: Mutex::default(),
            #[cfg(test)]
            sent: Mutex::default(),
        }
    }

    fn node_id(&self) -> Option<String> {
        match &self.identity {
            Identity::Node => peer::get_node_id().map(peer::normalize_node_id),
            Identity::Fixed(id) => Some(id.clone()),
        }
    }

    /// Whether this node may run the background work of `plugin` now. Writes
    /// the lease commit when it has to create, renew or take over.
    pub async fn holds(&self, db: &Db, drive: &str, plugin: &str) -> bool {
        let Some(me) = self.node_id() else {
            return true;
        };
        let key = (drive.to_string(), plugin.to_string());
        let now = self.clock.now_ms();
        if self
            .held
            .lock()
            .unwrap()
            .get(&key)
            .is_some_and(|v| now < v.until)
        {
            return true;
        }

        let leases = match read_leases(db, plugin, now).await {
            Ok(leases) => leases,
            Err(e) => {
                tracing::warn!(plugin, "cannot read leases: {e}");
                return false;
            }
        };
        if leases.is_empty() && !has_peers(db, drive) {
            self.remember(key, now + SOLO_RECHECK_MS);
            return true;
        }

        let all = leases.clone();
        let verdict = match head(leases) {
            None => self
                .write(db, plugin, &me, now, 0, None)
                .await
                .map(|_| now + RENEW_BEFORE_MS),
            Some(h) if h.holder == me => {
                if h.expires_at - now > RENEW_BEFORE_MS {
                    Ok(h.expires_at - RENEW_BEFORE_MS)
                } else {
                    self.renew(db, &h, now)
                        .await
                        .map(|_| now + TTL_MS - RENEW_BEFORE_MS)
                }
            }
            Some(h) if now < h.expires_at => {
                Err(format!("held by {} until {}", h.holder, h.expires_at))
            }
            Some(h) => match h.generation.checked_add(1) {
                // `read_leases` bounds generations, so this is a guard.
                None => Err("the head lease has no generation left".to_string()),
                Some(next) => self
                    .write(db, plugin, &me, now, next, Some(&h.subject))
                    .await
                    .map(|_| now + TTL_MS - RENEW_BEFORE_MS),
            },
        };
        match verdict {
            Ok(until) => {
                collect_old(db, &all).await;
                self.remember(key, until);
                true
            }
            Err(reason) => {
                tracing::debug!(plugin, "not running background work here: {reason}");
                self.held.lock().unwrap().remove(&key);
                false
            }
        }
    }

    async fn write(
        &self,
        db: &Db,
        plugin: &str,
        me: &str,
        now: i64,
        generation: i64,
        previous: Option<&str>,
    ) -> Result<(), String> {
        let mut lease = Resource::new("did:ad:placeholder".into());
        let mut set = |property: &str, value: Value| {
            lease
                .set_unsafe(property.into(), value)
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        set(urls::IS_A, Value::ResourceArray(vec![urls::LEASE.into()]))?;
        set(urls::PARENT, Value::AtomicUrl(plugin.into()))?;
        set(urls::LEASE_OF, Value::AtomicUrl(plugin.into()))?;
        set(urls::LEASE_HOLDER, Value::String(me.to_string()))?;
        set(urls::LEASE_EXPIRES_AT, Value::Timestamp(now + TTL_MS))?;
        set(urls::LEASE_GENERATION, Value::Integer(generation))?;
        if let Some(previous) = previous {
            set(urls::PREVIOUS_LEASE, Value::AtomicUrl(previous.into()))?;
        }
        let response = lease.save_as_genesis(db).await.map_err(|e| e.to_string())?;
        self.sent(response.commit);
        Ok(())
    }

    async fn renew(&self, db: &Db, held: &Lease, now: i64) -> Result<(), String> {
        let mut lease = db
            .get_resource(&held.subject.as_str().into())
            .await
            .map_err(|e| e.to_string())?;
        lease
            .set_unsafe(
                urls::LEASE_EXPIRES_AT.into(),
                Value::Timestamp(now + TTL_MS),
            )
            .map_err(|e| e.to_string())?;
        let response = lease.save(db).await.map_err(|e| e.to_string())?;
        self.sent(response.commit);
        Ok(())
    }

    #[cfg(test)]
    fn sent(&self, commit: atomic_lib::commit::Commit) {
        self.sent.lock().unwrap().push(commit);
    }

    #[cfg(not(test))]
    fn sent(&self, _: atomic_lib::commit::Commit) {}

    fn remember(&self, key: (String, String), until: i64) {
        self.held.lock().unwrap().insert(key, Verdict { until });
    }
}

fn has_peers(db: &Db, drive: &str) -> bool {
    peer::get_known_peers(db)
        .iter()
        .any(|p| p.drives.iter().any(|d| d == drive))
}

/// The highest generation that can exist at `now`. A generation only goes up
/// by a takeover, which needs the lease before it to have run out, so there is
/// at most one per [`TTL_MS`]; anything above this was not written by a node
/// following the protocol. The slack covers clock skew between nodes.
fn max_generation(now: i64) -> i64 {
    now.max(0) / TTL_MS + 2
}

/// The leases that count for `plugin` (an Installation): children of it
/// whose genesis was signed by an agent that may write it, with a plausible
/// generation. A `Lease` anywhere else naming it, or signed by someone with no
/// say over it, is not a lease of it: the whole store is queried, so this is
/// what keeps another drive, or another user, from deciding who runs it.
async fn read_leases(db: &Db, plugin: &str, now: i64) -> Result<Vec<Lease>, String> {
    let guarded = db
        .get_resource(&plugin.into())
        .await
        .map_err(|e| format!("{plugin} could not be read: {e}"))?;
    let result = db
        .query(&Query::new_prop_val(urls::LEASE_OF, plugin))
        .await
        .map_err(|e| e.to_string())?;
    let mut accepted = Vec::new();
    for resource in &result.resources {
        let Some(lease) = Lease::read(resource) else {
            continue;
        };
        let child = resource.get(urls::PARENT).is_ok_and(|parent| {
            canonicalize_scheme(&parent.to_string()) == canonicalize_scheme(plugin)
        });
        if !child
            || !resource.has_class(urls::LEASE)
            || !(0..=max_generation(now)).contains(&lease.generation)
        {
            tracing::debug!(lease = %lease.subject, "ignoring a lease that is not one of {plugin}");
            continue;
        }
        let Some(signer) = creator(db, resource).await else {
            continue;
        };
        let signer = ForAgent::AgentSubject(signer.into());
        if check_write(db, &guarded, &signer).await.is_err() {
            tracing::debug!(lease = %lease.subject, "ignoring a lease signed by an agent that may not write {plugin}");
            continue;
        }
        accepted.push(lease);
    }
    Ok(accepted)
}

/// Who signed the genesis of `lease`. A lease is named by its genesis
/// signature, so the commit that carries that signature is the one that
/// created it, and its signer was checked when it was applied. (The lease
/// writer does not mint a genesis certificate, so [`Resource::genesis_signer`]
/// has nothing to read; it answers first for a resource that has one.)
async fn creator(db: &Db, lease: &Resource) -> Option<String> {
    if let Some(signer) = lease.genesis_signer() {
        return Some(signer);
    }
    let subject = lease.get_subject().to_string();
    let signature = identifier_body(&subject)?;
    let commit = db
        .get_resource(&commit_subject(signature).as_str().into())
        .await
        .ok()?;
    commit.get(urls::SIGNER).ok().map(|s| s.to_string())
}

/// Removes the leases that are more than one takeover behind the head. The
/// head and the lease it took over stay (that is the trail a reader follows);
/// the rest only make every later read longer. Best effort.
async fn collect_old(db: &Db, leases: &[Lease]) {
    let Some(newest) = leases.iter().map(|l| l.generation).max() else {
        return;
    };
    for old in leases
        .iter()
        .filter(|l| l.generation.saturating_add(1) < newest)
    {
        let removed = match db.get_resource(&old.subject.as_str().into()).await {
            Ok(mut resource) => resource.destroy(db).await.map(|_| ()),
            Err(e) => Err(e),
        };
        if let Err(e) = removed {
            tracing::debug!(lease = %old.subject, "cannot remove an old lease: {e}");
        }
    }
}

/// A clock the test moves by hand.
#[cfg(test)]
pub struct ManualClock(std::sync::atomic::AtomicI64);

#[cfg(test)]
impl ManualClock {
    pub fn new(at: i64) -> Self {
        Self(std::sync::atomic::AtomicI64::new(at))
    }

    pub fn advance(&self, ms: i64) {
        self.0.fetch_add(ms, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
impl Clock for ManualClock {
    fn now_ms(&self) -> i64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atomic_lib::commit::CommitOpts;

    const DRIVE: &str = "did:ad:drive";

    async fn node_db(name: &str) -> Db {
        let db = Db::init_temp(name).await.unwrap();
        peer::add_known_peer_for_drive(&db, "other-node", "other", DRIVE);
        db
    }

    fn sync_opts() -> CommitOpts {
        CommitOpts {
            validate_schema: true,
            validate_constraints: true,
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: false,
            validate_loro_causality: false,
            update_index: true,
            validate_for_agent: None,
            source_id: None,
        }
    }

    /// What a sync does for these resources: applies the commits a node wrote
    /// to the other nodes' dbs.
    async fn ship(from: &Leases, to: &[&Db]) {
        let sent = std::mem::take(&mut *from.sent.lock().unwrap());
        for commit in sent {
            for db in to {
                db.apply_commit(commit.clone(), &sync_opts()).await.unwrap();
            }
        }
    }

    /// The thing the leases guard, on every node, writable by every node's
    /// agent (a lease only counts when its signer may write the Installation).
    async fn plugin_on(dbs: &[&Db]) -> String {
        let agents: Vec<String> = dbs
            .iter()
            .map(|db| db.get_default_agent().unwrap().subject.to_string())
            .collect();
        let mut plugin = Resource::new("did:ad:placeholder".into());
        plugin
            .set_unsafe(urls::NAME.into(), Value::String("Installation".into()))
            .unwrap();
        plugin
            .set_unsafe(
                urls::WRITE.into(),
                Value::ResourceArray(agents.iter().map(|a| a.as_str().into()).collect()),
            )
            .unwrap();
        let response = plugin.save_as_genesis(dbs[0]).await.unwrap();
        for db in &dbs[1..] {
            db.apply_commit(response.commit.clone(), &sync_opts())
                .await
                .unwrap();
        }
        plugin.get_subject().to_string()
    }

    async fn head_of(db: &Db, plugin: &str, now: i64) -> Lease {
        head(read_leases(db, plugin, now).await.unwrap()).unwrap()
    }

    /// A lease as a node would write it, with the pieces a test bends.
    async fn forged(
        db: &Db,
        parent: &str,
        of: &str,
        generation: i64,
        signer: Option<&atomic_lib::agents::Agent>,
    ) -> String {
        let mut lease = Resource::new("did:ad:placeholder".into());
        let mut set = |property: &str, value: Value| {
            lease.set_unsafe(property.into(), value).unwrap();
        };
        set(urls::IS_A, Value::ResourceArray(vec![urls::LEASE.into()]));
        set(urls::PARENT, Value::AtomicUrl(parent.into()));
        set(urls::LEASE_OF, Value::AtomicUrl(of.into()));
        set(urls::LEASE_HOLDER, Value::String("evil".into()));
        set(urls::LEASE_EXPIRES_AT, Value::Timestamp(0));
        set(urls::LEASE_GENERATION, Value::Integer(generation));
        match signer {
            Some(agent) => lease.save_as_genesis_signed_by(agent, db).await,
            None => lease.save_as_genesis(db).await,
        }
        .unwrap();
        lease.get_subject().to_string()
    }

    #[test]
    fn the_head_does_not_depend_on_arrival_order() {
        let lease = |subject: &str, holder: &str, generation| Lease {
            subject: subject.into(),
            holder: holder.into(),
            expires_at: 0,
            generation,
            previous: None,
        };
        let all = vec![
            lease("s1", "b", 1),
            lease("s2", "a", 1),
            lease("s3", "a", 0),
            lease("s4", "c", 1),
        ];
        // Highest generation, then lowest node id.
        assert_eq!(head(all.clone()).unwrap().subject, "s2");
        let mut reversed = all;
        reversed.reverse();
        assert_eq!(head(reversed).unwrap().subject, "s2");
        // The same holder twice at one generation: lowest subject.
        assert_eq!(
            head([lease("y", "a", 2), lease("x", "a", 2)])
                .unwrap()
                .subject,
            "x"
        );
    }

    #[actix_rt::test]
    async fn concurrent_takeover_converges_on_one_holder() {
        let (db_a, db_b, db_c) = (
            node_db("lease_conc_a").await,
            node_db("lease_conc_b").await,
            node_db("lease_conc_c").await,
        );
        let plugin = plugin_on(&[&db_a, &db_b, &db_c]).await;
        let clock = Arc::new(ManualClock::new(1_000_000));
        let a = Leases::with("node-a", clock.clone());
        let b = Leases::with("node-b", clock.clone());
        let c = Leases::with("node-c", clock.clone());

        // A writes the first lease; B and C receive it.
        assert!(a.holds(&db_a, DRIVE, &plugin).await);
        ship(&a, &[&db_b, &db_c]).await;
        let first = head_of(&db_a, &plugin, clock.now_ms()).await;
        assert_eq!(first.holder, "node-a");

        // It runs out. B and C each see it expired and take over, neither
        // having seen the other's lease: both think they hold it.
        clock.advance(TTL_MS + 1);
        assert!(b.holds(&db_b, DRIVE, &plugin).await);
        assert!(c.holds(&db_c, DRIVE, &plugin).await);
        assert_eq!(
            head_of(&db_b, &plugin, clock.now_ms()).await.holder,
            "node-b"
        );
        assert_eq!(
            head_of(&db_c, &plugin, clock.now_ms()).await.holder,
            "node-c"
        );

        // After the sync every node, A included, names the same head.
        ship(&b, &[&db_a, &db_c]).await;
        ship(&c, &[&db_a, &db_b]).await;
        for db in [&db_a, &db_b, &db_c] {
            let h = head_of(db, &plugin, clock.now_ms()).await;
            assert_eq!((h.holder.as_str(), h.generation), ("node-b", 1));
            assert_eq!(h.previous.as_deref(), Some(first.subject.as_str()));
        }

        // Past the cached verdicts, only the lowest id holds.
        clock.advance(RENEW_BEFORE_MS + 1);
        assert!(b.holds(&db_b, DRIVE, &plugin).await);
        assert!(!c.holds(&db_c, DRIVE, &plugin).await);
        assert!(!a.holds(&db_a, DRIVE, &plugin).await);
        assert_eq!(
            head_of(&db_b, &plugin, clock.now_ms()).await.generation,
            1,
            "renewed in place"
        );
    }

    #[actix_rt::test]
    async fn a_node_with_no_peers_and_no_lease_writes_nothing() {
        let db = Db::init_temp("lease_solo").await.unwrap();
        let plugin = plugin_on(&[&db]).await;
        let clock = Arc::new(ManualClock::new(1_000_000));
        let solo = Leases::with("node-a", clock);
        assert!(solo.holds(&db, DRIVE, &plugin).await);
        assert!(read_leases(&db, &plugin, 1_000_000)
            .await
            .unwrap()
            .is_empty());
        assert!(solo.sent.lock().unwrap().is_empty());
    }

    #[actix_rt::test]
    async fn leases_that_are_not_the_installations_own_are_ignored() {
        let db = node_db("lease_forged").await;
        let plugin = plugin_on(&[&db]).await;
        let other_drive = plugin_on(&[&db]).await;
        let outsider = atomic_lib::agents::Agent::new(None).unwrap();
        let now = 1_000_000;

        // Names the Installation, but lives under something else (another
        // drive's folder): not a child of the Installation.
        forged(&db, &other_drive, &plugin, 5, None).await;
        // A child of the Installation, signed by an agent with no say over it.
        forged(&db, &plugin, &plugin, 6, Some(&outsider)).await;
        assert!(read_leases(&db, &plugin, now).await.unwrap().is_empty());

        // The real thing is still read, next to the forgeries.
        let real = forged(&db, &plugin, &plugin, 0, None).await;
        let leases = read_leases(&db, &plugin, now).await.unwrap();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].subject, real);
    }

    #[actix_rt::test]
    async fn an_absurd_generation_neither_panics_nor_wins() {
        let db = node_db("lease_huge").await;
        let plugin = plugin_on(&[&db]).await;
        let clock = Arc::new(ManualClock::new(1_000_000));
        let node = Leases::with("node-a", clock.clone());
        // Signed by an agent that may write the Installation, expired, and so
        // large that taking it over would overflow.
        forged(&db, &plugin, &plugin, i64::MAX, None).await;
        forged(&db, &plugin, &plugin, -1, None).await;

        assert!(node.holds(&db, DRIVE, &plugin).await);
        let head = head_of(&db, &plugin, clock.now_ms()).await;
        assert_eq!((head.holder.as_str(), head.generation), ("node-a", 0));
    }

    #[actix_rt::test]
    async fn leases_more_than_one_takeover_behind_the_head_are_removed() {
        let db = node_db("lease_gc").await;
        let plugin = plugin_on(&[&db]).await;
        let clock = Arc::new(ManualClock::new(1_000_000));
        let node = Leases::with("node-a", clock.clone());
        for generation in 0..4 {
            forged(&db, &plugin, &plugin, generation, None).await;
        }

        assert!(node.holds(&db, DRIVE, &plugin).await);

        // The head (3) took over 2, so those two stay; 0 and 1 are gone. The
        // takeover this node wrote (4) is the new head.
        let mut left: Vec<_> = read_leases(&db, &plugin, clock.now_ms())
            .await
            .unwrap()
            .into_iter()
            .map(|l| l.generation)
            .collect();
        left.sort();
        assert_eq!(left, vec![2, 3, 4]);
    }
}
