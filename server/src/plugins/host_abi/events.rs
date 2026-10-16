//! `atomic:host/events`: the pull stream.
//!
//! The stream is the drive's durable event log (`atomic_lib::db::drive_events`),
//! one row per applied commit. This side adds what the log does not have: the
//! app's filters, its checkpoint, and the rights check. An app never sees an
//! event for a resource it cannot read, so the log can name every subject.

use atomic_lib::{
    db::drive_events::{DriveEvent, EventFilter},
    Storelike, Subject,
};

use super::{
    bindings::atomic::host::events::{self, Event, Filter, Kind},
    code, error,
    run::{AbiHost, AbiState},
    HostError,
};

/// Most events one `next` returns.
const MAX_EVENTS: u32 = 100;
/// Most log rows one `next` looks at, readable or not, so an app that cannot
/// read what is in front of it does not scan the log forever.
#[cfg(not(test))]
const MAX_SCAN: usize = 1000;
#[cfg(test)]
const MAX_SCAN: usize = 20;
/// Most batches of [`MAX_SCAN`] rows one `next` goes through while it has
/// found nothing to return.
const MAX_SCAN_BATCHES: usize = 4;
const FILTER_CAP: usize = 32;

fn parse_cursor(cursor: &str) -> Result<u64, HostError> {
    cursor.parse().map_err(|_| {
        error(
            code::INVALID_ARGUMENT,
            "the cursor is not one this host gave",
        )
    })
}

/// Whether the app's caller and Installation agent may read what the event
/// is about. A destroyed resource is gone, so its parent is asked.
async fn may_see(host: &AbiHost, event: &DriveEvent) -> bool {
    {
        let db = &host.db;
        let candidates = std::iter::once(&event.subject)
            .filter(|_| !event.destroyed)
            .chain(event.parent.as_ref());
        for subject in candidates {
            if let Ok(resource) = db.get_resource(&Subject::from(subject.clone())).await {
                return host.core.grant().check_read(db, &resource).await.is_ok();
            }
        }
        false
    }
}

impl events::Host for AbiState {
    async fn set_filters(&mut self, filters: Vec<Filter>) -> Result<(), HostError> {
        if filters.len() > FILTER_CAP {
            return Err(error(
                code::INVALID_ARGUMENT,
                format!("an app may hold at most {FILTER_CAP} filters"),
            ));
        }
        let filters: Vec<_> = filters
            .into_iter()
            .map(|f| EventFilter {
                class: f.class,
                subtree: f.subtree,
                property: f.property,
            })
            .collect();
        let app = &self.host;
        app.db
            .set_event_filters(&app.drive, &app.installation, &filters)
            .map_err(|e| error(code::INTERNAL, e.to_string()))
    }

    async fn next(&mut self, cursor: Option<String>, max: u32) -> Result<Vec<Event>, HostError> {
        let (db, drive, app) = (
            &self.host.db,
            &self.host.drive,
            self.host.installation.clone(),
        );
        let after_checkpoint = cursor.is_none();
        let after = match cursor {
            Some(c) => parse_cursor(&c)?,
            None => db.event_checkpoint(drive, &app),
        };
        // Commits are logged from the first read of an app on the drive.
        db.enable_drive_events(drive)
            .map_err(|e| error(code::INTERNAL, e.to_string()))?;
        let filters = db.event_filters(drive, &app);
        let needs_ancestors = filters
            .as_ref()
            .is_some_and(|fs| fs.iter().any(|f| f.subtree.is_some()));
        let max = max.clamp(1, MAX_EVENTS) as usize;

        let mut out = Vec::new();
        let mut from = after;
        for _ in 0..MAX_SCAN_BATCHES {
            let batch = db.drive_events(drive, from, MAX_SCAN);
            let Some(last) = batch.last().map(|e| e.seq) else {
                break;
            };
            let scanned = batch.len();
            for event in batch {
                let ancestors = if needs_ancestors {
                    db.event_ancestors(event.parent.as_deref()).await
                } else {
                    None
                };
                let wanted = filters
                    .as_ref()
                    .is_none_or(|fs| fs.iter().any(|f| f.matches(&event, ancestors.as_deref())));
                if wanted && may_see(&self.host, &event).await {
                    out.push(Event {
                        cursor: event.seq.to_string(),
                        kind: if event.destroyed {
                            Kind::Destroyed
                        } else {
                            Kind::Commit(event.subject.clone())
                        },
                        subject: Some(event.subject),
                        at_ms: event.at_ms.max(0) as u64,
                    });
                    if out.len() == max {
                        break;
                    }
                }
            }
            if !out.is_empty() {
                break;
            }
            // Everything looked at was filtered out or not visible, so there is
            // no event to ack past it: the app would look at the same rows on
            // every call and never reach what comes after. The checkpoint moves
            // over them, as the trigger path does for edges nobody wants.
            if after_checkpoint {
                db.ack_events(drive, &app, last)
                    .map_err(|e| error(code::INTERNAL, e.to_string()))?;
            }
            from = last;
            if scanned < MAX_SCAN {
                break;
            }
        }
        if out.is_empty() && !after_checkpoint && from > after {
            // An app that passes its own cursor has no checkpoint to move, so
            // without this it would be handed `[]` and the same cursor again,
            // for ever, in front of a long run it cannot see.
            out.push(Event {
                cursor: from.to_string(),
                kind: Kind::Progress,
                subject: None,
                at_ms: 0,
            });
        }
        Ok(out)
    }

    async fn ack(&mut self, cursor: String) -> Result<(), HostError> {
        let up_to = parse_cursor(&cursor)?;
        let app = &self.host;
        app.db
            .ack_events(&app.drive, &app.installation, up_to)
            .map_err(|e| error(code::INTERNAL, e.to_string()))
    }
}
