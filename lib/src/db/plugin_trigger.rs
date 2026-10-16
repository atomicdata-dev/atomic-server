//! What makes a plugin run when the data changes.
//!
//! Host state keyed by `(drive, plugin)`, for the same reason a schedule is:
//! a plugin's schema is created per drive, so the property subjects that would
//! hold this are not knowable to a Rust process reacting to an index event.
//!
//! The edges themselves come free. The store already watches queries for
//! `SUBSCRIBE_QUERY` and broadcasts `DbEvent::QueryMembershipChanged` whenever
//! a resource enters or leaves one. A trigger is a standing claim on those
//! events by something other than a WebSocket.

use serde::{Deserialize, Serialize};

use crate::db::plugin_schedule::AutoApplyGrant;
use crate::db::query_index::QueryFilter;
use crate::AtomicError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginTriggerKey {
    pub drive: String,
    pub plugin: String,
}

/// Most edges [`Db::pending_trigger_events`] counts.
pub const PENDING_COUNT_CAP: usize = 1000;

impl PluginTriggerKey {
    pub fn new(drive: &str, plugin: &str) -> Self {
        Self {
            drive: drive.to_string(),
            plugin: plugin.to_string(),
        }
    }
}

/// Which side of a membership change to run on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Edge {
    /// A resource started matching the query.
    Enter,
    /// A resource stopped matching it.
    Leave,
}

impl Edge {
    pub fn of(added: bool) -> Self {
        if added {
            Self::Enter
        } else {
            Self::Leave
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Enter => "enter",
            Self::Leave => "leave",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginTrigger {
    /// The query being watched. Drive-scoped, as every watched query must be.
    pub query: QueryFilter,
    pub on_enter: bool,
    pub on_leave: bool,
    /// When set, a triggered run writes instead of waiting for review. Same
    /// grant, same rules, as the one a schedule carries.
    #[serde(default)]
    pub auto_apply: Option<AutoApplyGrant>,
    pub last_error: Option<String>,
    /// Principal authorizing reads during unattended execution.
    #[serde(default)]
    pub run_as: Option<String>,
    #[serde(default)]
    pub pending_verdict: Option<String>,
}

impl PluginTrigger {
    pub fn new(query: QueryFilter, on_enter: bool, on_leave: bool) -> Result<Self, AtomicError> {
        // A trigger that fires on nothing is not a trigger, and storing one
        // would leave a plugin looking armed while it can never run.
        if !on_enter && !on_leave {
            return Err("A trigger must run on at least one of enter or leave".into());
        }

        Ok(Self {
            run_as: None,
            pending_verdict: None,
            query,
            on_enter,
            on_leave,
            auto_apply: None,
            last_error: None,
        })
    }

    pub fn wants(&self, edge: Edge) -> bool {
        match edge {
            Edge::Enter => self.on_enter,
            Edge::Leave => self.on_leave,
        }
    }
}

/// What a caller may see.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginTriggerInfo {
    pub queued_events: usize,
    pub query: QueryFilter,
    pub on_enter: bool,
    pub on_leave: bool,
    pub auto_apply: Option<AutoApplyGrant>,
    pub last_error: Option<String>,
    pub pending_verdict: Option<String>,
}

impl From<&PluginTrigger> for PluginTriggerInfo {
    fn from(trigger: &PluginTrigger) -> Self {
        Self {
            queued_events: 0,
            query: trigger.query.clone(),
            on_enter: trigger.on_enter,
            on_leave: trigger.on_leave,
            auto_apply: trigger.auto_apply.clone(),
            last_error: trigger.last_error.clone(),
            pending_verdict: trigger.pending_verdict.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter() -> QueryFilter {
        QueryFilter {
            filters: Vec::new(),
            sort_by: None,
            drive: "https://x/drive".into(),
        }
    }

    #[test]
    fn a_trigger_that_fires_on_nothing_is_refused() {
        assert!(PluginTrigger::new(filter(), false, false).is_err());
        assert!(PluginTrigger::new(filter(), true, false).is_ok());
        assert!(PluginTrigger::new(filter(), false, true).is_ok());
    }

    #[test]
    fn an_edge_is_wanted_only_when_asked_for() {
        let enter_only = PluginTrigger::new(filter(), true, false).unwrap();

        assert!(enter_only.wants(Edge::Enter));
        assert!(!enter_only.wants(Edge::Leave));
    }
}

/// One query edge from the drive's event log, plus the progress a run has
/// saved for it. The trigger's cursor stays below it until it is acknowledged,
/// so a restart resumes this event instead of repeating or losing it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedEvent {
    pub id: String,
    /// The event's sequence number in the drive's log.
    pub seq: u64,
    pub key: PluginTriggerKey,
    pub subject: String,
    pub edge: Edge,
    pub at: i64,
    pub verdict: Option<String>,
    pub waiting_for_review: bool,
    #[serde(default)]
    pub authorization: Option<String>,
}

fn consumer(key: &PluginTriggerKey) -> String {
    format!("trigger/{}", key.plugin)
}

fn head_key(key: &PluginTriggerKey) -> Vec<u8> {
    format!(
        "trigger-head/v1/{}/{}",
        super::drive_events::pure(&key.drive),
        key.plugin
    )
    .into_bytes()
}

impl crate::Db {
    /// Every stored trigger.
    pub fn plugin_triggers(
        &self,
    ) -> crate::errors::AtomicResult<Vec<(PluginTriggerKey, PluginTrigger)>> {
        self.kv
            .iter_tree(super::trees::Tree::PluginTrigger)
            .map(|entry| {
                let (key, value) = entry?;
                Ok((
                    PluginTriggerKey::from_bytes(&key)?,
                    PluginTrigger::from_bytes(&value)?,
                ))
            })
            .collect()
    }

    /// The trigger's next edge: the one a run already saved progress on, else
    /// the first one in the drive's log after the trigger's cursor. Events
    /// that are not this trigger's edges move the cursor past themselves.
    pub fn next_trigger_event(
        &self,
        key: &PluginTriggerKey,
        trigger: &PluginTrigger,
    ) -> crate::errors::AtomicResult<Option<QueuedEvent>> {
        if let Some(saved) = self
            .kv
            .get(super::trees::Tree::PluginMeta, &head_key(key))?
        {
            return Ok(Some(serde_json::from_slice(&saved)?));
        }
        let name = consumer(key);
        let after = self.event_checkpoint(&key.drive, &name);
        let mut last = after;
        for (event, edge) in self.trigger_edges(trigger, &key.drive, after, 1000)? {
            if let Some(edge) = edge {
                return Ok(Some(QueuedEvent {
                    id: format!("{:020}", event.seq),
                    seq: event.seq,
                    key: key.clone(),
                    subject: event.subject,
                    edge,
                    at: event.at_ms,
                    verdict: None,
                    waiting_for_review: false,
                    authorization: None,
                }));
            }
            last = event.seq;
        }
        if last > after {
            self.ack_events(&key.drive, &name, last)?;
        }
        Ok(None)
    }

    /// The log after `after`, each event with the edge this trigger wants from
    /// it (None when it is not one).
    fn trigger_edges(
        &self,
        trigger: &PluginTrigger,
        drive: &str,
        after: u64,
        max: usize,
    ) -> crate::errors::AtomicResult<Vec<(super::drive_events::DriveEvent, Option<Edge>)>> {
        let query = hex::encode(crate::db::query_index::query_id(&trigger.query)?);
        Ok(self
            .drive_events(drive, after, max)
            .into_iter()
            .map(|event| {
                let edge = event
                    .edges
                    .iter()
                    .find(|(q, _)| *q == query)
                    .map(|(_, enter)| Edge::of(*enter))
                    .filter(|edge| trigger.wants(*edge));
                (event, edge)
            })
            .collect())
    }

    /// How many edges the trigger has not finished, counted up to
    /// [`PENDING_COUNT_CAP`]: a backlog beyond that is "a lot", and counting it
    /// would read the whole log.
    pub fn pending_trigger_events(
        &self,
        key: &PluginTriggerKey,
        trigger: &PluginTrigger,
    ) -> crate::errors::AtomicResult<usize> {
        let mut after = self.event_checkpoint(&key.drive, &consumer(key));
        let mut pending = 0;
        loop {
            let page = self.trigger_edges(trigger, &key.drive, after, 1000)?;
            let Some((last, _)) = page.last() else {
                return Ok(pending);
            };
            after = last.seq;
            pending += page.iter().filter(|(_, edge)| edge.is_some()).count();
            if pending >= PENDING_COUNT_CAP {
                return Ok(PENDING_COUNT_CAP);
            }
        }
    }

    /// Saves a run's progress on its event.
    pub fn save_plugin_event(&self, event: &QueuedEvent) -> crate::errors::AtomicResult<()> {
        self.kv.insert(
            super::trees::Tree::PluginMeta,
            &head_key(&event.key),
            &serde_json::to_vec(event)?,
        )?;
        self.flush()
    }

    /// The event is done: forget its progress and move the cursor past it.
    pub fn acknowledge_plugin_event(&self, event: &QueuedEvent) -> crate::errors::AtomicResult<()> {
        self.kv
            .remove(super::trees::Tree::PluginMeta, &head_key(&event.key))?;
        self.ack_events(&event.key.drive, &consumer(&event.key), event.seq)?;
        self.flush()
    }

    /// Starts a new trigger at the end of the log; an old trigger keeps its cursor.
    pub(crate) fn start_trigger_cursor(
        &self,
        key: &PluginTriggerKey,
    ) -> crate::errors::AtomicResult<()> {
        self.enable_drive_events(&key.drive)?;
        let latest = self.last_event_seq(&key.drive);
        self.ack_events(&key.drive, &consumer(key), latest)
    }

    pub(crate) fn forget_trigger_cursor(
        &self,
        key: &PluginTriggerKey,
    ) -> crate::errors::AtomicResult<()> {
        self.kv
            .remove(super::trees::Tree::PluginMeta, &head_key(key))?;
        self.forget_event_consumer(&key.drive, &consumer(key))
    }
}
