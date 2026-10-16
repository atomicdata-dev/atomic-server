//! One durable, ordered event stream per drive.
//!
//! Every applied commit appends one row in the same batch that stores it, so a
//! crash never leaves a change without its event or an event without its
//! change. Rows live in `Tree::PluginMeta` under
//! `drive-event/v1/<drive>/<seq, 20 digits>`; the sequence only grows, so a
//! cursor is "the last `seq` I handled" and survives a restart. A consumer's
//! filters and checkpoint are stored beside it (`event-sub/v1`, `event-ck/v1`),
//! keyed by drive and consumer.
//!
//! The stream carries no rights. It says what changed; whoever reads it checks
//! what the reader may see (`atomic-server`'s `events` interface does).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::trees::{Method, Operation, Transaction, Tree};
use crate::{errors::AtomicResult, Db, Resource, Storelike, Subject};

const EVENT_PREFIX: &str = "drive-event/v1/";
/// Events older than this are dropped when a new one is appended.
const RETENTION_MS: i64 = 7 * 24 * 3600 * 1000;

/// What happened to one resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriveEvent {
    pub seq: u64,
    /// As the rest of the API names it. Compare with [`pure`] on both sides.
    pub subject: String,
    pub destroyed: bool,
    /// The classes the resource had (before the commit, for a destroy).
    pub classes: Vec<String>,
    /// The resource's parent. The chain above it is resolved when the event is
    /// read ([`Db::event_ancestors`]), so the row stays small.
    pub parent: Option<String>,
    /// The properties the commit changed.
    pub props: BTreeSet<String>,
    pub at_ms: i64,
    /// The watched queries this commit moved the resource into (`true`) or out
    /// of, by hex query id. Only queries a plugin trigger watches are listed.
    /// Triggers read their enter and leave edges from here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edges: Vec<(String, bool)>,
}

/// Which events a consumer wants. Every field that is set must match.
/// `ancestors` are the event's [`Db::event_ancestors`]; None when the walk
/// failed, which never matches a subtree filter above the resource itself.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventFilter {
    pub class: Option<String>,
    /// The resource itself or anything below it.
    pub subtree: Option<String>,
    pub property: Option<String>,
}

impl EventFilter {
    pub fn matches(&self, event: &DriveEvent, ancestors: Option<&[String]>) -> bool {
        self.class
            .as_ref()
            .is_none_or(|c| event.classes.contains(c))
            && self.subtree.as_ref().is_none_or(|s| {
                let s = pure(s);
                pure(&event.subject) == s || ancestors.is_some_and(|a| a.contains(&s))
            })
            && self
                .property
                .as_ref()
                .is_none_or(|p| event.destroyed || event.props.contains(p))
    }
}

/// The subject as the log compares it (no query, no drive hint).
pub fn pure(subject: &str) -> String {
    Subject::from(subject.to_string()).pure_id()
}

/// The first key after every key that starts with `prefix`.
fn prefix_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    end.push(0xff);
    end
}

fn event_key(drive: &str, seq: u64) -> Vec<u8> {
    format!("{EVENT_PREFIX}{}/{seq:020}", pure(drive)).into_bytes()
}

fn consumer_key(kind: &str, drive: &str, consumer: &str) -> Vec<u8> {
    format!("{kind}/v1/{}/{consumer}", pure(drive)).into_bytes()
}

/// The event for an applied commit, before it has a sequence number.
pub(crate) struct PendingEvent {
    drive: String,
    event: DriveEvent,
}

impl PendingEvent {
    /// None when the drive has no app that reads events.
    pub(crate) async fn new(
        store: &Db,
        resource: &Resource,
        destroyed: bool,
        props: BTreeSet<String>,
    ) -> Option<Self> {
        let classes: Vec<String> = resource
            .get(crate::urls::IS_A)
            .ok()
            .and_then(|v| v.to_subjects(None).ok())
            .unwrap_or_default();
        // No drive logs yet (the common case, and every first-run `populate`):
        // nothing to find, and walking parents here would only read.
        let installation = classes.iter().any(|c| c == crate::urls::INSTALLATION);
        if !installation && !store.any_drive_events() {
            return None;
        }
        let parent = resource
            .get(crate::urls::PARENT)
            .ok()
            .map(|v| pure(&v.to_string()));
        // A resource written without rights checks carries no `drive`; the top
        // of its parent chain is the drive then.
        let drive = match resource.get_drive() {
            Some(drive) => drive.pure_id(),
            None => store.event_ancestors(parent.as_deref()).await?.pop()?,
        };
        if installation {
            store.enable_drive_events(&drive).ok()?;
        } else if !store.drive_events_enabled(&drive) {
            return None;
        }
        Some(Self {
            drive,
            event: DriveEvent {
                seq: 0,
                subject: resource.get_subject().to_string(),
                destroyed,
                classes,
                parent,
                props,
                at_ms: crate::utils::now(),
                edges: Vec::new(),
            },
        })
    }

    /// The subject the event is about, as [`pure`] names it.
    pub(crate) fn subject_id(&self) -> String {
        pure(&self.event.subject)
    }

    pub(crate) fn with_edges(mut self, edges: Vec<(String, bool)>) -> Self {
        self.event.edges = edges;
        self
    }
}

impl Db {
    /// The parents above `parent`, nearest first, up to the drive. None if a
    /// link cannot be read.
    pub async fn event_ancestors(&self, parent: Option<&str>) -> Option<Vec<String>> {
        let mut chain: Vec<String> = Vec::new();
        let mut next = parent.map(pure);
        while let Some(p) = next {
            if chain.len() >= 64 || chain.contains(&p) {
                break;
            }
            let up = match self.get_resource(&Subject::from(p.clone())).await {
                Ok(r) => r
                    .get(crate::urls::PARENT)
                    .ok()
                    .map(|v| pure(&v.to_string())),
                Err(_) if chain.is_empty() => None,
                Err(_) => return None,
            };
            chain.push(p);
            next = up;
        }
        Some(chain)
    }

    /// Whether any drive logs its commits.
    pub(crate) fn any_drive_events(&self) -> bool {
        if self.drive_events_on.read().is_ok_and(|s| !s.is_empty()) {
            return true;
        }
        let prefix = b"event-on/v1/";
        self.kv
            .range_page(Tree::PluginMeta, prefix.to_vec(), prefix_end(prefix), 1)
            .is_ok_and(|rows| !rows.is_empty())
    }

    /// Whether commits on this drive are logged: only drives with an app.
    pub fn drive_events_enabled(&self, drive: &str) -> bool {
        let drive = pure(drive);
        if self
            .drive_events_on
            .read()
            .is_ok_and(|s| s.contains(&drive))
        {
            return true;
        }
        let on = self
            .kv
            .get(Tree::PluginMeta, &consumer_key("event-on", &drive, ""))
            .ok()
            .flatten()
            .is_some();
        if on {
            if let Ok(mut s) = self.drive_events_on.write() {
                s.insert(drive);
            }
        }
        on
    }

    /// Starts logging this drive (an Installation was written, or an app read).
    pub fn enable_drive_events(&self, drive: &str) -> AtomicResult<()> {
        if self.drive_events_enabled(drive) {
            return Ok(());
        }
        self.kv
            .insert(Tree::PluginMeta, &consumer_key("event-on", drive, ""), b"1")?;
        if let Ok(mut s) = self.drive_events_on.write() {
            s.insert(pure(drive));
        }
        Ok(())
    }

    /// Gives `pending` the next sequence number of its drive and queues its
    /// row. The caller holds `drive_event_seq` (the guard) until the batch has
    /// landed, so rows become visible in sequence order.
    pub(crate) fn queue_drive_event(
        &self,
        pending: PendingEvent,
        last: &mut std::collections::HashMap<String, u64>,
        transaction: &mut Transaction,
    ) -> AtomicResult<()> {
        let PendingEvent { drive, mut event } = pending;
        let seq = match last.get(&drive) {
            Some(seq) => *seq,
            None => self
                .drive_events(&drive, 0, usize::MAX)
                .last()
                .map_or(0, |e| e.seq),
        } + 1;
        last.insert(drive.clone(), seq);
        event.seq = seq;
        transaction.push(Operation {
            tree: Tree::PluginMeta,
            method: Method::Insert,
            key: event_key(&drive, seq),
            val: Some(serde_json::to_vec(&event)?),
        });
        // Old rows go with a later write, so no sweeper has to run.
        let cutoff = event.at_ms - RETENTION_MS;
        for old in self
            .drive_events(&drive, 0, 64)
            .into_iter()
            .filter(|_| seq % 64 == 0)
        {
            if old.at_ms >= cutoff {
                break;
            }
            transaction.push(Operation {
                tree: Tree::PluginMeta,
                method: Method::Delete,
                key: event_key(&drive, old.seq),
                val: None,
            });
        }
        Ok(())
    }

    /// Up to `max` events of `drive` with a sequence number above `after`.
    pub fn drive_events(&self, drive: &str, after: u64, max: usize) -> Vec<DriveEvent> {
        let prefix = format!("{EVENT_PREFIX}{}/", pure(drive));
        self.kv
            .scan_prefix(Tree::PluginMeta, prefix.as_bytes())
            .flatten()
            // The key ends in the sequence number: skip rows already handled
            // without decoding them.
            .filter(|(k, _)| {
                std::str::from_utf8(k)
                    .ok()
                    .and_then(|k| k.rsplit('/').next()?.parse::<u64>().ok())
                    .is_none_or(|seq| seq > after)
            })
            .filter_map(|(_, v)| serde_json::from_slice::<DriveEvent>(&v).ok())
            .filter(|e| e.seq > after)
            .take(max)
            .collect()
    }

    /// The filters a consumer subscribed with. None: it never subscribed.
    pub fn event_filters(&self, drive: &str, consumer: &str) -> Option<Vec<EventFilter>> {
        let bytes = self
            .kv
            .get(
                Tree::PluginMeta,
                &consumer_key("event-sub", drive, consumer),
            )
            .ok()??;
        serde_json::from_slice(&bytes).ok()
    }

    pub fn set_event_filters(
        &self,
        drive: &str,
        consumer: &str,
        filters: &[EventFilter],
    ) -> AtomicResult<()> {
        self.kv.insert(
            Tree::PluginMeta,
            &consumer_key("event-sub", drive, consumer),
            &serde_json::to_vec(filters)?,
        )?;
        self.enable_drive_events(drive)?;
        self.flush()
    }

    /// Everything up to this sequence number is handled.
    pub fn event_checkpoint(&self, drive: &str, consumer: &str) -> u64 {
        self.kv
            .get(Tree::PluginMeta, &consumer_key("event-ck", drive, consumer))
            .ok()
            .flatten()
            .and_then(|b| String::from_utf8(b).ok()?.parse().ok())
            .unwrap_or(0)
    }

    /// Moves the checkpoint forward; it never moves back.
    pub fn ack_events(&self, drive: &str, consumer: &str, up_to: u64) -> AtomicResult<()> {
        if up_to <= self.event_checkpoint(drive, consumer) {
            return Ok(());
        }
        self.kv.insert(
            Tree::PluginMeta,
            &consumer_key("event-ck", drive, consumer),
            up_to.to_string().as_bytes(),
        )?;
        self.flush()
    }

    /// Forgets a consumer's filters and checkpoint (it was uninstalled).
    pub fn forget_event_consumer(&self, drive: &str, consumer: &str) -> AtomicResult<()> {
        for kind in ["event-sub", "event-ck"] {
            self.kv
                .remove(Tree::PluginMeta, &consumer_key(kind, drive, consumer))?;
        }
        Ok(())
    }
}
