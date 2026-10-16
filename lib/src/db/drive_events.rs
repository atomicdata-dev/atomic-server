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
    /// Parent first, up to the drive. Kept because a destroyed resource can no
    /// longer be asked.
    pub ancestors: Vec<String>,
    /// The properties the commit changed.
    pub props: BTreeSet<String>,
    pub signer: String,
    pub at_ms: i64,
}

/// Which events a consumer wants. Every field that is set must match.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventFilter {
    pub class: Option<String>,
    /// The resource itself or anything below it.
    pub subtree: Option<String>,
    pub property: Option<String>,
}

impl EventFilter {
    pub fn matches(&self, event: &DriveEvent) -> bool {
        self.class
            .as_ref()
            .is_none_or(|c| event.classes.contains(c))
            && self.subtree.as_ref().is_none_or(|s| {
                let s = pure(s);
                pure(&event.subject) == s || event.ancestors.contains(&s)
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
    pub(crate) async fn new(
        store: &Db,
        resource: &Resource,
        destroyed: bool,
        props: BTreeSet<String>,
        signer: &str,
    ) -> Option<Self> {
        let classes = resource
            .get(crate::urls::IS_A)
            .ok()
            .and_then(|v| v.to_subjects(None).ok())
            .unwrap_or_default();
        let mut ancestors: Vec<String> = Vec::new();
        let mut next = resource
            .get(crate::urls::PARENT)
            .ok()
            .map(|v| v.to_string());
        while let Some(parent) = next.filter(|_| ancestors.len() < 64) {
            let parent = pure(&parent);
            if ancestors.contains(&parent) {
                break;
            }
            next = match store.get_resource(&Subject::from(parent.clone())).await {
                Ok(p) => p.get(crate::urls::PARENT).ok().map(|v| v.to_string()),
                Err(_) => None,
            };
            ancestors.push(parent);
        }
        // A resource written without rights checks carries no `drive`; the top
        // of its parent chain is the drive then.
        let drive = match resource.get_drive() {
            Some(drive) => drive.pure_id(),
            None => ancestors.last()?.clone(),
        };
        Some(Self {
            drive,
            event: DriveEvent {
                seq: 0,
                subject: resource.get_subject().to_string(),
                destroyed,
                classes,
                ancestors,
                props,
                signer: signer.to_string(),
                at_ms: crate::utils::now(),
            },
        })
    }
}

impl Db {
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
