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
}

impl PluginTrigger {
    pub fn new(query: QueryFilter, on_enter: bool, on_leave: bool) -> Result<Self, AtomicError> {
        // A trigger that fires on nothing is not a trigger, and storing one
        // would leave a plugin looking armed while it can never run.
        if !on_enter && !on_leave {
            return Err("A trigger must run on at least one of enter or leave".into());
        }

        Ok(Self {
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
    pub query: QueryFilter,
    pub on_enter: bool,
    pub on_leave: bool,
    pub auto_apply: Option<AutoApplyGrant>,
    pub last_error: Option<String>,
}

impl From<&PluginTrigger> for PluginTriggerInfo {
    fn from(trigger: &PluginTrigger) -> Self {
        Self {
            query: trigger.query.clone(),
            on_enter: trigger.on_enter,
            on_leave: trigger.on_leave,
            auto_apply: trigger.auto_apply.clone(),
            last_error: trigger.last_error.clone(),
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
