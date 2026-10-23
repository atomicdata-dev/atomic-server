//! Looking for this agent's other devices: again and again, not once.
//!
//! A device that was signed in with the secret (not paired by QR) knows no
//! other device. The only way it finds one is the directory every device
//! announces itself in (the drive's pkarr record in the apps), and the
//! devices that are already connected to each other never look there again.
//! Looking once at start-up and then saying "no peers online" for good is
//! what left a freshly installed tablet alone next to three online devices.
//!
//! [`PeerSearch`] owns that search for a host:
//! - [`PeerSearch::start_with`] starts the transport once: a second caller
//!   while a start is under way waits for it and shares its result, a failed
//!   start is not remembered (the next caller tries again);
//! - [`PeerSearch::run`] looks up the announced devices of the drives, dials
//!   the ones that are not this device and not live yet, and repeats with a
//!   backoff while nobody is found (and slower once connected, so a device
//!   installed later is still found); [`PeerSearch::search_again`] (a
//!   button, a network change, the app coming back) cuts the wait short;
//! - [`PeerSearch::status`] says which of those it is doing, in words a
//!   screen can show, and why.
//!
//! The directory and the dialer are seams ([`PeerDirectory`], [`PeerDialer`]):
//! the Flutter bridge binds them to pkarr and Iroh; the tests bind them to
//! fakes, or to two in-process Iroh nodes.

use async_trait::async_trait;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Where devices announce themselves for a drive.
#[async_trait]
pub trait PeerDirectory: Send + Sync {
    /// Every node id announced for `drive`, this device's own included.
    /// `Err` when the directory could not be asked (no network, a relay that
    /// does not answer): not the same as nobody having announced.
    async fn announced(&self, drive: &str) -> Result<Vec<String>, String>;

    /// Announce this device for `drive`.
    async fn announce(&self, drive: &str, me: &str) -> Result<(), String>;
}

/// How devices are reached.
#[async_trait]
pub trait PeerDialer: Send + Sync {
    /// Connect to `node_id` and sync `drive` with it (it stays live after).
    async fn dial(&self, node_id: &str, drive: &str) -> Result<(), String>;

    /// Node ids with a live connection now.
    fn live(&self) -> Vec<String>;
}

/// What the search is doing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PeerSearchState {
    /// The transport is not up yet.
    Starting,
    /// A lookup or a dial is under way.
    Searching,
    /// Looked, nobody (else) answered; looking again in `retry_in_secs`.
    NoPeersYet { retry_in_secs: u64 },
    /// Live with this many devices.
    Connected { devices: usize },
    /// Could not look at all (the transport did not start, the directory could
    /// not be reached). Retried too, after `retry_in_secs`.
    Failed { reason: String, retry_in_secs: u64 },
}

/// [`PeerSearchState`] plus what a screen needs around it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PeerSearchStatus {
    #[serde(flatten)]
    pub state: PeerSearchState,
    /// One line for the screen.
    pub message: String,
    /// Why, for a details line: what the directory said, what each dial said.
    pub detail: Option<String>,
    /// Unix ms of the last finished round.
    pub last_checked_ms: Option<u64>,
    /// Rounds since the search last found somebody (or since it started).
    pub attempts: u32,
}

impl PeerSearchStatus {
    fn new(
        state: PeerSearchState,
        detail: Option<String>,
        last: Option<u64>,
        attempts: u32,
    ) -> Self {
        PeerSearchStatus {
            message: message_for(&state),
            state,
            detail,
            last_checked_ms: last,
            attempts,
        }
    }
}

fn message_for(state: &PeerSearchState) -> String {
    match state {
        PeerSearchState::Starting => "Getting ready to look for devices…".into(),
        PeerSearchState::Searching => "Looking for devices…".into(),
        PeerSearchState::NoPeersYet { .. } => "No other device found yet".into(),
        PeerSearchState::Connected { devices } => format!(
            "Connected to {devices} device{}",
            if *devices == 1 { "" } else { "s" }
        ),
        PeerSearchState::Failed { reason, .. } => format!("Can't look for devices: {reason}"),
    }
}

/// When to look again.
#[derive(Debug, Clone)]
pub struct PeerSearchSchedule {
    /// Waits after a round that found nobody, one per round in a row; the last
    /// repeats.
    pub idle: Vec<Duration>,
    /// Wait after a round that left this device connected: slow, but a device
    /// installed later is still found.
    pub connected: Duration,
    /// A device that did not answer is skipped for this long (doubling per
    /// failure, up to `idle`'s last × 8) unless the search was asked for.
    pub dead_node: Duration,
}

impl Default for PeerSearchSchedule {
    fn default() -> Self {
        PeerSearchSchedule {
            // Quick first rounds so a freshly opened app finds its devices
            // within seconds, then slowly: every round asks the public
            // directory, and after ~4 minutes without a result another round
            // every 5 minutes is plenty (anything explicit still dials at
            // once and starts over, see `search_again`).
            idle: [5, 10, 15, 30, 60, 120, 300]
                .map(Duration::from_secs)
                .to_vec(),
            connected: Duration::from_secs(300),
            dead_node: Duration::from_secs(30),
        }
    }
}

impl PeerSearchSchedule {
    fn idle_wait(&self, round: u32) -> Duration {
        let i = (round as usize).min(self.idle.len().saturating_sub(1));
        self.idle.get(i).copied().unwrap_or(Duration::from_secs(15))
    }
}

/// How many devices are dialled in one round. A drive's record keeps the
/// replicas of uninstalled apps too, so this is more than one.
const DIALS_PER_ROUND: usize = 4;

/// The outcome of one round, for a host that runs rounds itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundOutcome {
    /// Other devices the directory named.
    pub announced: Vec<String>,
    /// Devices dialled this round.
    pub dialled: Vec<String>,
    /// Live devices after the round.
    pub live: usize,
}

#[derive(Default)]
struct DeadNode {
    failures: u32,
    retry_at: Option<Instant>,
}

pub struct PeerSearch {
    schedule: PeerSearchSchedule,
    status: Mutex<PeerSearchStatus>,
    wake: tokio::sync::Notify,
    /// The transport's node id once started (see [`Self::start_with`]).
    started: tokio::sync::Mutex<Option<String>>,
    running: std::sync::atomic::AtomicBool,
    /// Set by [`Self::search_again`]: the next round dials every device, the
    /// ones that did not answer recently too.
    forced: std::sync::atomic::AtomicBool,
    /// The app is in the background: [`Self::run`] makes no directory call
    /// (no lookup, no announce) until [`Self::set_paused`] says otherwise.
    paused: std::sync::atomic::AtomicBool,
    dead: Mutex<HashMap<String, DeadNode>>,
}

/// Node ids compare case-insensitively, without spaces around them.
fn norm(id: &str) -> String {
    id.trim().to_ascii_lowercase()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl PeerSearch {
    pub fn new(schedule: PeerSearchSchedule) -> Arc<Self> {
        Arc::new(PeerSearch {
            schedule,
            status: Mutex::new(PeerSearchStatus::new(
                PeerSearchState::Starting,
                None,
                None,
                0,
            )),
            wake: tokio::sync::Notify::new(),
            started: tokio::sync::Mutex::new(None),
            running: false.into(),
            forced: false.into(),
            paused: false.into(),
            dead: Mutex::new(HashMap::new()),
        })
    }

    pub fn status(&self) -> PeerSearchStatus {
        self.status.lock().unwrap().clone()
    }

    fn set(&self, state: PeerSearchState, detail: Option<String>, finished_round: bool) {
        let mut status = self.status.lock().unwrap();
        let attempts = match &state {
            PeerSearchState::Connected { .. } => 0,
            _ if finished_round => status.attempts + 1,
            _ => status.attempts,
        };
        let last = if finished_round {
            Some(now_ms())
        } else {
            status.last_checked_ms
        };
        *status = PeerSearchStatus::new(state, detail, last, attempts);
    }

    /// Look again now: a "Search again" button, a network change, the app
    /// coming back to the foreground. Devices that did not answer recently are
    /// dialled too.
    pub fn search_again(&self) {
        self.forced.store(true, std::sync::atomic::Ordering::SeqCst);
        self.wake.notify_one();
    }

    /// Pause (the app went to the background) or resume the loop of
    /// [`Self::run`]. While paused it asks the directory nothing and
    /// announces nothing; live connections are not touched. Resuming looks
    /// again at once, like [`Self::search_again`].
    pub fn set_paused(&self, paused: bool) {
        let was = self
            .paused
            .swap(paused, std::sync::atomic::Ordering::SeqCst);
        if was && !paused {
            self.search_again();
        }
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Start the transport once. A caller that comes while a start is under
    /// way waits for it and gets its node id; a failed start is reported in
    /// the status and not remembered, so the next caller tries again.
    pub async fn start_with<F, Fut>(&self, start: F) -> Result<String, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<String, String>>,
    {
        let mut started = self.started.lock().await;
        if let Some(id) = started.as_ref() {
            return Ok(id.clone());
        }
        self.set(PeerSearchState::Starting, None, false);
        match start().await {
            Ok(id) => {
                *started = Some(id.clone());
                Ok(id)
            }
            Err(e) => {
                self.set(
                    PeerSearchState::Failed {
                        reason: format!("the connection did not start ({e})"),
                        retry_in_secs: 0,
                    },
                    Some(e.clone()),
                    true,
                );
                Err(e)
            }
        }
    }

    /// The node id [`Self::start_with`] started, if it did.
    pub async fn node_id(&self) -> Option<String> {
        self.started.lock().await.clone()
    }

    /// One round: announce (when asked), look up every drive, dial the
    /// devices that are not this one and not live yet. Sets the status.
    pub async fn search_once(
        &self,
        me: &str,
        drives: &[String],
        directory: &dyn PeerDirectory,
        dialer: &dyn PeerDialer,
        announce: bool,
    ) -> RoundOutcome {
        let forced = self.forced.swap(false, std::sync::atomic::Ordering::SeqCst);
        if forced {
            // Asked for: start over with the quick rounds.
            self.status.lock().unwrap().attempts = 0;
        }
        self.set(PeerSearchState::Searching, None, false);
        let me = norm(me);
        let mut drives: Vec<&String> = drives.iter().collect();
        drives.dedup();

        if announce {
            for drive in &drives {
                if let Err(e) = directory.announce(drive, &me).await {
                    tracing::info!("[peer_search] announce for {drive} failed: {e}");
                }
            }
        }

        // Each other device with the first drive it was announced for.
        let mut announced: Vec<(String, String)> = Vec::new();
        let mut lookup_errors = Vec::new();
        for drive in &drives {
            match directory.announced(drive).await {
                Ok(ids) => {
                    for id in ids {
                        let id = norm(&id);
                        // Our own id in the record is the normal case for a
                        // drive on this device: never a reason to stop.
                        if id.is_empty() || id == me || announced.iter().any(|(a, _)| *a == id) {
                            continue;
                        }
                        announced.push((id, drive.to_string()));
                    }
                }
                Err(e) => lookup_errors.push(e),
            }
        }

        let live: Vec<String> = dialer.live().iter().map(|i| norm(i)).collect();
        let now = Instant::now();
        let to_dial: Vec<(String, String)> = {
            let dead = self.dead.lock().unwrap();
            announced
                .iter()
                .filter(|(id, _)| !live.contains(id))
                .filter(|(id, _)| {
                    forced
                        || dead
                            .get(id)
                            .and_then(|d| d.retry_at)
                            .is_none_or(|at| at <= now)
                })
                .take(DIALS_PER_ROUND)
                .cloned()
                .collect()
        };

        let results = futures::future::join_all(
            to_dial
                .iter()
                .map(|(id, drive)| async move { (id.clone(), dialer.dial(id, drive).await) }),
        )
        .await;
        let mut dial_errors = Vec::new();
        {
            let mut dead = self.dead.lock().unwrap();
            for (id, result) in &results {
                match result {
                    Ok(()) => {
                        dead.remove(id);
                    }
                    Err(e) => {
                        let entry = dead.entry(id.clone()).or_default();
                        entry.failures += 1;
                        let cap = self.schedule.idle_wait(u32::MAX) * 8;
                        let wait = (self.schedule.dead_node
                            * 2u32.saturating_pow(entry.failures.saturating_sub(1)))
                        .min(cap.max(self.schedule.dead_node));
                        entry.retry_at = Some(Instant::now() + wait);
                        dial_errors.push(format!("{}: {e}", &id[..id.len().min(12)]));
                    }
                }
            }
        }

        let live_after = dialer.live().len();
        let outcome = RoundOutcome {
            announced: announced.iter().map(|(id, _)| id.clone()).collect(),
            dialled: to_dial.iter().map(|(id, _)| id.clone()).collect(),
            live: live_after,
        };
        tracing::info!(
            "[peer_search] round: {} drive(s), {} other device(s) announced, {} dialled, {} live, lookup errors: {:?}, dial errors: {:?}",
            drives.len(),
            outcome.announced.len(),
            outcome.dialled.len(),
            live_after,
            lookup_errors,
            dial_errors
        );

        let retry_in_secs = self.schedule.idle_wait(self.status().attempts).as_secs();
        if live_after > 0 {
            self.set(
                PeerSearchState::Connected {
                    devices: live_after,
                },
                None,
                true,
            );
        } else if announced.is_empty() && !lookup_errors.is_empty() {
            self.set(
                PeerSearchState::Failed {
                    reason: "the device directory could not be reached".into(),
                    retry_in_secs,
                },
                Some(lookup_errors.join(" · ")),
                true,
            );
        } else {
            let detail = if !dial_errors.is_empty() {
                format!(
                    "{} other device{} announced, none answered: {}",
                    announced.len(),
                    if announced.len() == 1 { "" } else { "s" },
                    dial_errors.join(" · ")
                )
            } else if !announced.is_empty() {
                format!(
                    "{} other device{} announced, none answered recently; trying again later",
                    announced.len(),
                    if announced.len() == 1 { "" } else { "s" },
                )
            } else {
                "No other device has announced this workspace yet. Open the app on another \
                 device signed in with the same account, or pair with a QR code."
                    .to_string()
            };
            let detail = if lookup_errors.is_empty() {
                detail
            } else {
                format!("{detail} ({})", lookup_errors.join(" · "))
            };
            self.set(
                PeerSearchState::NoPeersYet { retry_in_secs },
                Some(detail),
                true,
            );
        }
        outcome
    }

    /// Search until the process ends: a round, then a wait that depends on
    /// what it found ([`PeerSearchSchedule`]), cut short by
    /// [`Self::search_again`]. Announces on the first round and every
    /// `announce_every` after. `drives` is read each round (the active drive
    /// changes). Only the first call runs; later calls return at once.
    pub async fn run<D>(
        self: Arc<Self>,
        me: String,
        drives: D,
        directory: Arc<dyn PeerDirectory>,
        dialer: Arc<dyn PeerDialer>,
        announce_every: Duration,
    ) where
        D: Fn() -> Vec<String> + Send + Sync,
    {
        if self.running.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let mut last_announce: Option<Instant> = None;
        // The drives announced for at `last_announce`. A different list (a
        // sign-in moved this device to the secret's drive) announces at once:
        // the other devices look for us in that drive, not in the old one.
        let mut announced_for: Vec<String> = Vec::new();
        loop {
            // In the background: no directory traffic at all. A resume (or
            // anything else that wakes the loop) is noticed here.
            while self.is_paused() {
                self.wake.notified().await;
            }
            let list = drives();
            let announce = last_announce.is_none_or(|t| t.elapsed() >= announce_every)
                || (!list.is_empty() && list != announced_for);
            let wait = if list.is_empty() {
                self.set(
                    PeerSearchState::NoPeersYet {
                        retry_in_secs: self.schedule.idle_wait(0).as_secs(),
                    },
                    Some("No workspace on this device yet".into()),
                    true,
                );
                self.schedule.idle_wait(0)
            } else {
                let outcome = self
                    .search_once(&me, &list, directory.as_ref(), dialer.as_ref(), announce)
                    .await;
                if announce {
                    last_announce = Some(Instant::now());
                    announced_for = list;
                }
                if outcome.live > 0 {
                    self.schedule.connected
                } else {
                    self.schedule
                        .idle_wait(self.status().attempts.saturating_sub(1))
                }
            };
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = self.wake.notified() => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const ME: &str = "aaaa";
    const OTHER: &str = "bbbb";
    const DRIVE: &str = "did:ad:drive";

    #[derive(Default)]
    struct FakeDirectory {
        /// Answers per call, the last repeats. `Err` = unreachable.
        answers: Mutex<Vec<Result<Vec<String>, String>>>,
        lookups: AtomicUsize,
        announces: AtomicUsize,
    }

    impl FakeDirectory {
        fn answering(answers: Vec<Result<Vec<&str>, &str>>) -> Arc<Self> {
            Arc::new(FakeDirectory {
                answers: Mutex::new(
                    answers
                        .into_iter()
                        .map(|a| {
                            a.map(|ids| ids.into_iter().map(String::from).collect())
                                .map_err(String::from)
                        })
                        .collect(),
                ),
                ..Default::default()
            })
        }
    }

    #[async_trait]
    impl PeerDirectory for FakeDirectory {
        async fn announced(&self, _drive: &str) -> Result<Vec<String>, String> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            let mut answers = self.answers.lock().unwrap();
            if answers.len() > 1 {
                answers.remove(0)
            } else {
                answers[0].clone()
            }
        }
        async fn announce(&self, _drive: &str, _me: &str) -> Result<(), String> {
            self.announces.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Devices in `reachable` answer a dial and are live after it.
    #[derive(Default)]
    struct FakeDialer {
        reachable: Vec<String>,
        live: Mutex<Vec<String>>,
        dials: Mutex<Vec<String>>,
    }

    impl FakeDialer {
        fn reaching(ids: &[&str]) -> Arc<Self> {
            Arc::new(FakeDialer {
                reachable: ids.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            })
        }
    }

    #[async_trait]
    impl PeerDialer for FakeDialer {
        async fn dial(&self, node_id: &str, _drive: &str) -> Result<(), String> {
            self.dials.lock().unwrap().push(node_id.to_string());
            if self.reachable.iter().any(|r| r == node_id) {
                self.live.lock().unwrap().push(node_id.to_string());
                Ok(())
            } else {
                Err("timed out".into())
            }
        }
        fn live(&self) -> Vec<String> {
            self.live.lock().unwrap().clone()
        }
    }

    fn fast() -> PeerSearchSchedule {
        PeerSearchSchedule {
            idle: [20, 40].map(Duration::from_millis).to_vec(),
            connected: Duration::from_secs(60),
            dead_node: Duration::from_secs(60),
        }
    }

    fn drives() -> Vec<String> {
        vec![DRIVE.to_string()]
    }

    #[tokio::test]
    async fn a_start_while_another_is_under_way_shares_it() {
        let search = PeerSearch::new(fast());
        let starts = Arc::new(AtomicUsize::new(0));
        let start = |starts: Arc<AtomicUsize>| async move {
            starts.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok::<_, String>("node-1".to_string())
        };
        let (a, b) = tokio::join!(
            search.start_with(|| start(starts.clone())),
            search.start_with(|| start(starts.clone())),
        );
        assert_eq!(a.unwrap(), "node-1");
        assert_eq!(b.unwrap(), "node-1");
        assert_eq!(starts.load(Ordering::SeqCst), 1, "one endpoint, not two");
    }

    #[tokio::test]
    async fn a_failed_start_is_reported_and_tried_again() {
        let search = PeerSearch::new(fast());
        assert_eq!(search.status().state, PeerSearchState::Starting);
        let err = search
            .start_with(|| async { Err::<String, _>("address in use".to_string()) })
            .await;
        assert!(err.is_err());
        let status = search.status();
        assert!(
            matches!(status.state, PeerSearchState::Failed { .. }),
            "{status:?}"
        );
        assert!(
            status.message.starts_with("Can't look for devices"),
            "{}",
            status.message
        );
        assert_eq!(status.detail.as_deref(), Some("address in use"));
        let ok = search
            .start_with(|| async { Ok("node-2".to_string()) })
            .await;
        assert_eq!(ok.unwrap(), "node-2");
    }

    #[tokio::test]
    async fn announced_devices_are_dialled_and_our_own_id_does_not_block_them() {
        let search = PeerSearch::new(fast());
        // The record names this device first (it announced last), then two
        // others, one of which is gone.
        let directory = FakeDirectory::answering(vec![Ok(vec![ME, "dead", OTHER])]);
        let dialer = FakeDialer::reaching(&[OTHER]);
        let outcome = search
            .search_once(ME, &drives(), directory.as_ref(), dialer.as_ref(), true)
            .await;
        assert_eq!(outcome.announced, vec!["dead", OTHER]);
        assert!(!dialer.dials.lock().unwrap().contains(&ME.to_string()));
        assert_eq!(outcome.live, 1);
        assert_eq!(directory.announces.load(Ordering::SeqCst), 1);
        let status = search.status();
        assert_eq!(status.state, PeerSearchState::Connected { devices: 1 });
        assert_eq!(status.message, "Connected to 1 device");
    }

    #[tokio::test]
    async fn only_our_own_id_is_no_peers_yet_not_a_failure() {
        let search = PeerSearch::new(fast());
        let directory = FakeDirectory::answering(vec![Ok(vec![ME])]);
        let dialer = FakeDialer::reaching(&[]);
        search
            .search_once(ME, &drives(), directory.as_ref(), dialer.as_ref(), false)
            .await;
        let status = search.status();
        assert!(
            matches!(status.state, PeerSearchState::NoPeersYet { .. }),
            "{status:?}"
        );
        assert_eq!(status.message, "No other device found yet");
        assert!(status
            .detail
            .unwrap()
            .contains("No other device has announced"));
        assert!(dialer.dials.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_unreachable_directory_is_a_failure_with_its_reason() {
        let search = PeerSearch::new(fast());
        let directory = FakeDirectory::answering(vec![Err("pkarr relay unreachable: dns error")]);
        let dialer = FakeDialer::reaching(&[]);
        search
            .search_once(ME, &drives(), directory.as_ref(), dialer.as_ref(), false)
            .await;
        let status = search.status();
        assert!(
            matches!(status.state, PeerSearchState::Failed { .. }),
            "{status:?}"
        );
        assert!(status.detail.unwrap().contains("dns error"));
    }

    #[tokio::test]
    async fn a_device_that_did_not_answer_waits_unless_asked() {
        let search = PeerSearch::new(fast());
        let directory = FakeDirectory::answering(vec![Ok(vec!["dead"])]);
        let dialer = FakeDialer::reaching(&[]);
        for _ in 0..2 {
            search
                .search_once(ME, &drives(), directory.as_ref(), dialer.as_ref(), false)
                .await;
        }
        assert_eq!(
            dialer.dials.lock().unwrap().len(),
            1,
            "dead node skipped on the next round"
        );
        let status = search.status();
        assert!(status.detail.unwrap().contains("none answered"));
        search.search_again();
        search
            .search_once(ME, &drives(), directory.as_ref(), dialer.as_ref(), false)
            .await;
        assert_eq!(
            dialer.dials.lock().unwrap().len(),
            2,
            "search again dials it anyway"
        );
    }

    /// The bug: one lookup at start, "no peers online" for good. The loop
    /// keeps looking, and finds the device that announced itself later.
    #[tokio::test]
    async fn nobody_at_first_is_retried_until_somebody_comes() {
        let search = PeerSearch::new(fast());
        let directory =
            FakeDirectory::answering(vec![Ok(vec![ME]), Err("timeout"), Ok(vec![ME, OTHER])]);
        let dialer = FakeDialer::reaching(&[OTHER]);
        let run = tokio::spawn(search.clone().run(
            ME.into(),
            drives,
            directory.clone(),
            dialer.clone(),
            Duration::from_secs(3600),
        ));
        let deadline = Instant::now() + Duration::from_secs(5);
        while search.status().state != (PeerSearchState::Connected { devices: 1 }) {
            assert!(
                Instant::now() < deadline,
                "never connected: {:?}",
                search.status()
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(directory.lookups.load(Ordering::SeqCst) >= 3);
        assert_eq!(directory.announces.load(Ordering::SeqCst), 1);
        run.abort();
    }

    #[tokio::test]
    async fn retries_back_off_and_search_again_cuts_the_wait() {
        let search = PeerSearch::new(PeerSearchSchedule {
            idle: [Duration::from_millis(10), Duration::from_secs(3600)].to_vec(),
            connected: Duration::from_secs(3600),
            dead_node: Duration::from_secs(60),
        });
        let directory = FakeDirectory::answering(vec![Ok(vec![ME])]);
        let dialer = FakeDialer::reaching(&[]);
        let run = tokio::spawn(search.clone().run(
            ME.into(),
            drives,
            directory.clone(),
            dialer.clone(),
            Duration::from_secs(3600),
        ));
        // First round, then 10 ms, then a second; the third waits an hour.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(directory.lookups.load(Ordering::SeqCst), 2);
        let status = search.status();
        assert_eq!(
            status.state,
            PeerSearchState::NoPeersYet {
                retry_in_secs: 3600
            }
        );
        assert_eq!(status.attempts, 2);
        search.search_again();
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Cut short, and the backoff starts over (the quick 10 ms round follows).
        assert!(directory.lookups.load(Ordering::SeqCst) >= 3);
        run.abort();
    }

    #[test]
    fn the_default_schedule_backs_off_to_five_minutes() {
        let schedule = PeerSearchSchedule::default();
        let waits: Vec<u64> = (0..10).map(|r| schedule.idle_wait(r).as_secs()).collect();
        assert_eq!(waits, vec![5, 10, 15, 30, 60, 120, 300, 300, 300, 300]);
        assert_eq!(schedule.idle_wait(u32::MAX).as_secs(), 300);
        assert_eq!(schedule.connected.as_secs(), 300);
        // The quick rounds come first: within the first minute, five rounds.
        let first_minute: u64 = waits.iter().take(4).sum();
        assert!(first_minute <= 60);
    }

    #[tokio::test]
    async fn search_again_starts_over_with_the_quick_rounds() {
        let search = PeerSearch::new(PeerSearchSchedule {
            idle: [Duration::from_millis(10), Duration::from_secs(3600)].to_vec(),
            connected: Duration::from_secs(3600),
            dead_node: Duration::from_secs(60),
        });
        let directory = FakeDirectory::answering(vec![Ok(vec![ME])]);
        let dialer = FakeDialer::reaching(&[]);
        let run = tokio::spawn(search.clone().run(
            ME.into(),
            drives,
            directory.clone(),
            dialer.clone(),
            Duration::from_secs(3600),
        ));
        tokio::time::sleep(Duration::from_millis(200)).await;
        // Backed off to an hour after two rounds.
        assert_eq!(directory.lookups.load(Ordering::SeqCst), 2);
        assert!(search.status().attempts >= 2);
        search.search_again();
        tokio::time::sleep(Duration::from_millis(200)).await;
        // The asked-for round, then the quick 10 ms round again, then the hour.
        assert_eq!(directory.lookups.load(Ordering::SeqCst), 4);
        run.abort();
    }

    /// A sign-in moves the device to another drive; the others look for it
    /// there, so it announces there at once, not at the next periodic announce.
    #[tokio::test]
    async fn a_changed_drive_list_announces_again_before_the_periodic_announce() {
        let search = PeerSearch::new(fast());
        let directory = FakeDirectory::answering(vec![Ok(vec![ME])]);
        let dialer = FakeDialer::reaching(&[]);
        let current = Arc::new(Mutex::new(vec!["did:ad:old".to_string()]));
        let seen = current.clone();
        let run = tokio::spawn(search.clone().run(
            ME.into(),
            move || seen.lock().unwrap().clone(),
            directory.clone(),
            dialer.clone(),
            Duration::from_secs(3600),
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(directory.announces.load(Ordering::SeqCst), 1);
        // The same drives, searched again: no new announce.
        search.search_again();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(directory.announces.load(Ordering::SeqCst), 1);

        *current.lock().unwrap() = vec!["did:ad:new".to_string()];
        search.search_again();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(directory.announces.load(Ordering::SeqCst), 2);
        run.abort();
    }

    #[tokio::test]
    async fn paused_makes_no_directory_calls_and_resume_looks_at_once() {
        let search = PeerSearch::new(fast());
        search.set_paused(true);
        let directory = FakeDirectory::answering(vec![Ok(vec![ME])]);
        let dialer = FakeDialer::reaching(&[]);
        let run = tokio::spawn(search.clone().run(
            ME.into(),
            drives,
            directory.clone(),
            dialer.clone(),
            Duration::from_secs(3600),
        ));
        tokio::time::sleep(Duration::from_millis(150)).await;
        // Not even when asked: a wake in the background changes nothing.
        search.search_again();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(directory.lookups.load(Ordering::SeqCst), 0);
        assert_eq!(directory.announces.load(Ordering::SeqCst), 0);

        search.set_paused(false);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            directory.lookups.load(Ordering::SeqCst) >= 1,
            "looked at once"
        );
        assert_eq!(directory.announces.load(Ordering::SeqCst), 1);

        // Paused again: the rounds already scheduled stop.
        search.set_paused(true);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let seen = directory.lookups.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(directory.lookups.load(Ordering::SeqCst), seen);
        run.abort();
    }

    #[tokio::test]
    async fn a_second_run_does_not_start_a_second_loop() {
        let search = PeerSearch::new(fast());
        let directory = FakeDirectory::answering(vec![Ok(vec![ME])]);
        let dialer = FakeDialer::reaching(&[]);
        let first = tokio::spawn(search.clone().run(
            ME.into(),
            drives,
            directory.clone(),
            dialer.clone(),
            Duration::from_secs(3600),
        ));
        tokio::time::sleep(Duration::from_millis(5)).await;
        // Returns at once instead of looping.
        tokio::time::timeout(
            Duration::from_secs(1),
            search.clone().run(
                ME.into(),
                drives,
                directory.clone(),
                dialer.clone(),
                Duration::from_secs(3600),
            ),
        )
        .await
        .expect("second run returns");
        first.abort();
    }

    #[test]
    fn the_status_serializes_for_a_screen() {
        let status = PeerSearchStatus::new(
            PeerSearchState::NoPeersYet { retry_in_secs: 10 },
            Some("why".into()),
            Some(1),
            3,
        );
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["state"], "no_peers_yet");
        assert_eq!(json["retry_in_secs"], 10);
        assert_eq!(json["message"], "No other device found yet");
        assert_eq!(json["detail"], "why");
        assert_eq!(json["attempts"], 3);
    }
}
