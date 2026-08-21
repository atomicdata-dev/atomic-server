//! When a plugin should run unattended, and what the last unattended run found.
//!
//! Host state rather than resource properties, for the same reason secrets are:
//! a plugin's schema is created per drive, so its property subjects are not
//! knowable to a scheduler running in Rust. Keying by `(drive, plugin)` means
//! the loop can find what is due without resolving anyone's ontology.
//!
//! The verdict of a background run is kept here rather than applied. Nobody is
//! watching at 3am, and the whole model is that a run proposes and a person
//! approves — so the fetching happens unattended and the approving does not.

use serde::{Deserialize, Serialize};

use crate::AtomicError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginScheduleKey {
    pub drive: String,
    pub plugin: String,
}

impl PluginScheduleKey {
    pub fn new(drive: &str, plugin: &str) -> Self {
        Self {
            drive: drive.to_string(),
            plugin: plugin.to_string(),
        }
    }
}

/// Shortest interval a plugin may ask for.
///
/// Not a throttle for the server's sake — a plugin that runs every few seconds
/// will exhaust an API's rate limit and get the user's credential blocked, which
/// is a worse outcome than the run being late.
pub const MIN_INTERVAL_SECONDS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginSchedule {
    /// How often to run, in seconds.
    pub interval_seconds: u64,
    /// Milliseconds since the epoch. The loop picks up anything due.
    pub next_run_at: i64,
    pub last_run_at: Option<i64>,
    /// The verdict the last unattended run produced, as JSON, waiting for
    /// someone to review it. Absent when the run failed or wrote nothing.
    pub pending_verdict: Option<String>,
    /// Why the last run produced nothing. Kept so a plugin that has been
    /// failing silently for a week is visible rather than merely quiet.
    pub last_error: Option<String>,
}

impl PluginSchedule {
    pub fn new(interval_seconds: u64, now: i64) -> Result<Self, AtomicError> {
        if interval_seconds < MIN_INTERVAL_SECONDS {
            return Err(format!(
                "A plugin may run at most once every {MIN_INTERVAL_SECONDS} seconds",
            )
            .into());
        }

        Ok(Self {
            interval_seconds,
            next_run_at: now + (interval_seconds as i64) * 1000,
            last_run_at: None,
            pending_verdict: None,
            last_error: None,
        })
    }

    pub fn is_due(&self, now: i64) -> bool {
        now >= self.next_run_at
    }

    /// Moves the schedule past `now`.
    ///
    /// Skips missed windows rather than replaying them: a server that was off
    /// for a day should not wake up and run an importer fourteen hundred times.
    pub fn advance(&mut self, now: i64) {
        let step = (self.interval_seconds as i64) * 1000;
        self.last_run_at = Some(now);
        self.next_run_at = now + step;
    }

    pub fn record_verdict(&mut self, verdict: String) {
        self.pending_verdict = Some(verdict);
        self.last_error = None;
    }

    pub fn record_error(&mut self, error: String) {
        self.last_error = Some(error);
    }
}

/// What a caller may see. The verdict is included — it is a proposal, not a
/// credential — but it is the only thing here worth a size limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginScheduleInfo {
    pub interval_seconds: u64,
    pub next_run_at: i64,
    pub last_run_at: Option<i64>,
    pub pending_verdict: Option<String>,
    pub last_error: Option<String>,
}

impl From<&PluginSchedule> for PluginScheduleInfo {
    fn from(schedule: &PluginSchedule) -> Self {
        Self {
            interval_seconds: schedule.interval_seconds,
            next_run_at: schedule.next_run_at,
            last_run_at: schedule.last_run_at,
            pending_verdict: schedule.pending_verdict.clone(),
            last_error: schedule.last_error.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: u64 = 3600;

    #[test]
    fn a_new_schedule_is_not_immediately_due() {
        let schedule = PluginSchedule::new(HOUR, 1_000).unwrap();

        assert!(!schedule.is_due(1_000));
        assert!(!schedule.is_due(1_000 + 3_599_000));
        assert!(schedule.is_due(1_000 + 3_600_000));
    }

    #[test]
    fn too_frequent_is_refused_before_it_burns_a_rate_limit() {
        assert!(PluginSchedule::new(30, 0).is_err());
        assert!(PluginSchedule::new(MIN_INTERVAL_SECONDS, 0).is_ok());
    }

    #[test]
    fn a_server_that_was_off_does_not_replay_every_missed_window() {
        let mut schedule = PluginSchedule::new(HOUR, 0).unwrap();

        // Two weeks later. One run is owed, not three hundred and thirty-six.
        let now = 14 * 24 * 3_600_000;
        assert!(schedule.is_due(now));

        schedule.advance(now);

        assert_eq!(schedule.last_run_at, Some(now));
        assert!(!schedule.is_due(now));
        assert!(schedule.is_due(now + 3_600_000));
    }

    #[test]
    fn a_verdict_clears_the_previous_error() {
        let mut schedule = PluginSchedule::new(HOUR, 0).unwrap();

        schedule.record_error("offline".to_string());
        assert_eq!(schedule.last_error.as_deref(), Some("offline"));

        schedule.record_verdict("{}".to_string());
        assert_eq!(schedule.last_error, None);
        assert_eq!(schedule.pending_verdict.as_deref(), Some("{}"));
    }

    #[test]
    fn an_error_keeps_a_verdict_nobody_has_reviewed_yet() {
        let mut schedule = PluginSchedule::new(HOUR, 0).unwrap();

        schedule.record_verdict("{\"intents\":[]}".to_string());
        schedule.record_error("offline".to_string());

        // Losing it would discard work a person was going to approve.
        assert!(schedule.pending_verdict.is_some());
        assert_eq!(schedule.last_error.as_deref(), Some("offline"));
    }
}

#[cfg(all(test, feature = "db-redb"))]
mod store_tests {
    use super::*;
    use crate::db::Db;

    async fn db(name: &str) -> Db {
        Db::init_temp(&format!("plugin_schedules_{name}"))
            .await
            .expect("temp db")
    }

    #[tokio::test]
    async fn only_what_is_due_comes_back() {
        let db = db("due").await;
        let now = 10_000_000;

        let soon = PluginScheduleKey::new("did:ad:d", "did:ad:soon");
        let later = PluginScheduleKey::new("did:ad:d", "did:ad:later");

        db.set_plugin_schedule(&soon, &PluginSchedule::new(60, now - 120_000).unwrap())
            .unwrap();
        db.set_plugin_schedule(&later, &PluginSchedule::new(3600, now).unwrap())
            .unwrap();

        let due = db.due_plugin_schedules(now).unwrap();

        assert_eq!(due.len(), 1);
        assert_eq!(due[0].0.plugin, "did:ad:soon");
    }

    #[tokio::test]
    async fn a_key_survives_the_round_trip_it_is_scanned_through() {
        let db = db("roundtrip").await;
        let key = PluginScheduleKey::new("did:ad:drive-1", "did:ad:plugin-1");

        db.set_plugin_schedule(&key, &PluginSchedule::new(60, 0).unwrap())
            .unwrap();

        // The scan rebuilds the key from its bytes; a lossy encoding would send
        // a run to the wrong plugin.
        let due = db.due_plugin_schedules(120_000).unwrap();

        assert_eq!(due[0].0, key);
    }

    #[tokio::test]
    async fn a_deleted_schedule_stops_being_due() {
        let db = db("deleted").await;
        let key = PluginScheduleKey::new("did:ad:d", "did:ad:p");

        db.set_plugin_schedule(&key, &PluginSchedule::new(60, 0).unwrap())
            .unwrap();
        db.delete_plugin_schedule(&key).unwrap();

        assert!(db.due_plugin_schedules(999_999).unwrap().is_empty());
        assert!(db.get_plugin_schedule(&key).unwrap().is_none());
    }
}
