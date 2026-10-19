//! The Inbox of the person's private drive: the `Notification`s the web app
//! records there (`browser/data-browser/src/helpers/notifications/inbox.ts`),
//! read from the local store only, and marked read the way the web app does
//! (a `readAt` timestamp on the Notification).
//!
//! The private drive points to its Inbox with `notifications:inbox`; every
//! Notification is a child of that Inbox. Two devices can record the same
//! event, so a list shows one item per `notificationSource` (read when any
//! copy is), as the web app's list does.

use super::{rows::row_resource, LocalWritePusher};
use crate::{
    errors::AtomicResult, runtime::AtomicNode, storelike::Query, urls, Db, Storelike, Subject,
    Value,
};
use serde_json::{json, Value as Json};
use std::collections::HashMap;

/// `notifications:inbox`: on the private drive, the Inbox.
pub const INBOX: &str = "https://atomicdata.dev/properties/inbox";
/// The class of a Notification.
pub const NOTIFICATION: &str = "https://atomicdata.dev/classes/Notification";
/// The resource that caused the Notification (a Message).
pub const NOTIFICATION_SOURCE: &str = "https://atomicdata.dev/properties/notificationSource";
/// `chat`, `comment` or `reply`.
pub const NOTIFICATION_KIND: &str = "https://atomicdata.dev/properties/notificationKind";
/// The agent who did the thing.
pub const ACTOR: &str = "https://atomicdata.dev/properties/actor";
/// When it happened (ms).
pub const OCCURRED_AT: &str = "https://atomicdata.dev/properties/occurredAt";
/// When the recipient read it (ms); absent while unread.
pub const READ_AT: &str = "https://atomicdata.dev/properties/readAt";

struct Item {
    subject: String,
    json: Json,
    read: bool,
    occurred_at: i64,
}

fn text(resource: &crate::Resource, property: &str) -> String {
    resource
        .get(property)
        .map(|v| v.to_string())
        .unwrap_or_default()
}

/// The notifications of the person's Inbox, newest first, one per source, as
/// `[{subject, title, body, about, kind, actor, source, occurred_at, read}]`
/// (`title` is the Notification's `name`, `body` its `description`, `about`
/// what to open, "" when absent). Empty when there is no Inbox on this device.
pub async fn list_notifications(store: &Db, limit: usize) -> AtomicResult<Vec<Json>> {
    let Some(inbox) = super::lists::private_drive_list_one(store, INBOX).await? else {
        return Ok(Vec::new());
    };
    let members = store
        .query(&Query::new_prop_val(urls::PARENT, &inbox))
        .await?;

    let mut by_source: HashMap<String, Item> = HashMap::new();
    for subject in &members.subjects {
        let Some(n) = row_resource(store, &Subject::from(subject.as_str())).await else {
            continue;
        };
        let is_notification = n
            .get(urls::IS_A)
            .ok()
            .and_then(|v| v.to_subjects(None).ok())
            .is_some_and(|classes| classes.iter().any(|c| c == NOTIFICATION));
        if !is_notification {
            continue;
        }
        let subject = subject.to_string();
        let source = {
            let s = text(&n, NOTIFICATION_SOURCE);
            if s.is_empty() {
                subject.clone()
            } else {
                s
            }
        };
        let occurred_at = n
            .get(OCCURRED_AT)
            .ok()
            .and_then(|v| v.to_int().ok())
            .unwrap_or(0);
        let read = n.get(READ_AT).is_ok();
        let item = Item {
            json: json!({
                "subject": subject,
                "title": text(&n, urls::NAME),
                "body": text(&n, urls::DESCRIPTION),
                "about": text(&n, urls::ABOUT),
                "kind": text(&n, NOTIFICATION_KIND),
                "actor": text(&n, ACTOR),
                "source": source,
                "occurred_at": occurred_at,
                "read": read,
            }),
            subject,
            read,
            occurred_at,
        };
        // A read copy wins over an unread one; otherwise the newest.
        match by_source.get(&source) {
            Some(seen) if (seen.read, seen.occurred_at) >= (item.read, item.occurred_at) => {}
            _ => {
                by_source.insert(source, item);
            }
        }
    }

    let mut items: Vec<Item> = by_source.into_values().collect();
    items.sort_by(|a, b| {
        b.occurred_at
            .cmp(&a.occurred_at)
            .then_with(|| a.subject.cmp(&b.subject))
    });
    Ok(items.into_iter().take(limit).map(|i| i.json).collect())
}

/// Mark the Notification `subject` read (`readAt` = now), and every other
/// copy of the same source in the Inbox, so the item stays read on every
/// device. Already read ones are left alone. Returns how many were written.
pub async fn mark_notification_read(
    node: &AtomicNode,
    pusher: &dyn LocalWritePusher,
    subject: &str,
    now: i64,
) -> AtomicResult<usize> {
    let store = node.db();
    let source = {
        let n = store.get_resource(&Subject::from(subject)).await?;
        text(&n, NOTIFICATION_SOURCE)
    };
    let mut targets = vec![subject.to_string()];
    if !source.is_empty() {
        for other in list_copies(store, &source).await? {
            if !targets.contains(&other) {
                targets.push(other);
            }
        }
    }
    let mut written = 0;
    for target in targets {
        let mut n = store.get_resource(&Subject::from(target.as_str())).await?;
        if n.get(READ_AT).is_ok() {
            continue;
        }
        n.set_unsafe(READ_AT.into(), Value::Timestamp(now))?;
        let response = node.save_locally(&mut n).await?;
        pusher.push(&response).await;
        written += 1;
    }
    Ok(written)
}

/// The Notifications in the Inbox recorded for `source`.
async fn list_copies(store: &Db, source: &str) -> AtomicResult<Vec<String>> {
    let Some(inbox) = super::lists::private_drive_list_one(store, INBOX).await? else {
        return Ok(Vec::new());
    };
    let members = store
        .query(&Query::new_prop_val(urls::PARENT, &inbox))
        .await?;
    let mut out = Vec::new();
    for subject in &members.subjects {
        if let Some(n) = row_resource(store, &Subject::from(subject.as_str())).await {
            if text(&n, NOTIFICATION_SOURCE) == source {
                out.push(subject.to_string());
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{test_support::Device, NoPush};

    async fn inbox(d: &Device) -> String {
        let inbox = d
            .store
            .create_resource(
                "https://atomicdata.dev/classes/Inbox",
                &d.drive,
                "Inbox",
                None,
            )
            .await
            .unwrap();
        let mut drive = d
            .store
            .get_resource(&Subject::from(d.drive.as_str()))
            .await
            .unwrap();
        drive
            .set_unsafe(INBOX.into(), Value::AtomicUrl(inbox.as_str().into()))
            .unwrap();
        d.node.save_locally(&mut drive).await.unwrap();
        inbox
    }

    async fn notify(
        d: &Device,
        inbox: &str,
        title: &str,
        source: &str,
        at: i64,
        read: bool,
    ) -> String {
        let mut props = vec![
            (
                urls::ABOUT,
                Value::AtomicUrl("https://example.test/chat".into()),
            ),
            (urls::DESCRIPTION, Value::String("Hello there".into())),
            (NOTIFICATION_SOURCE, Value::AtomicUrl(source.into())),
            (NOTIFICATION_KIND, Value::String("chat".into())),
            (ACTOR, Value::AtomicUrl("https://example.test/agent".into())),
            (OCCURRED_AT, Value::Timestamp(at)),
        ];
        if read {
            props.push((READ_AT, Value::Timestamp(at + 1)));
        }
        d.store
            .create_resource(NOTIFICATION, inbox, title, Some(props))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn no_inbox_is_an_empty_list() {
        let d = Device::new().await;
        assert!(list_notifications(&d.store, 10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn notifications_are_listed_newest_first_with_their_read_state() {
        let d = Device::new().await;
        let inbox = inbox(&d).await;
        let old = notify(&d, &inbox, "Old", "https://example.test/m1", 1_000, true).await;
        let new = notify(&d, &inbox, "New", "https://example.test/m2", 9_000, false).await;
        // Not a notification: left out.
        d.store
            .create_resource(urls::FOLDER, &inbox, "Stray", None)
            .await
            .unwrap();

        let list = list_notifications(&d.store, 10).await.unwrap();
        assert_eq!(list.len(), 2, "{list:?}");
        assert_eq!(list[0]["subject"], new);
        assert_eq!(list[0]["title"], "New");
        assert_eq!(list[0]["body"], "Hello there");
        assert_eq!(list[0]["about"], "https://example.test/chat");
        assert_eq!(list[0]["kind"], "chat");
        assert_eq!(list[0]["occurred_at"], 9_000);
        assert_eq!(list[0]["read"], false);
        assert_eq!(list[1]["subject"], old);
        assert_eq!(list[1]["read"], true);

        assert_eq!(list_notifications(&d.store, 1).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn two_copies_of_one_source_are_one_item_read_if_either_is() {
        let d = Device::new().await;
        let inbox = inbox(&d).await;
        let source = "https://example.test/m1";
        notify(&d, &inbox, "Copy a", source, 1_000, false).await;
        let read = notify(&d, &inbox, "Copy b", source, 2_000, true).await;
        let list = list_notifications(&d.store, 10).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["subject"], read);
        assert_eq!(list[0]["read"], true);
    }

    #[tokio::test]
    async fn marking_read_sets_read_at_on_every_copy() {
        let d = Device::new().await;
        let inbox = inbox(&d).await;
        let source = "https://example.test/m1";
        let a = notify(&d, &inbox, "Copy a", source, 1_000, false).await;
        let b = notify(&d, &inbox, "Copy b", source, 2_000, false).await;
        let other = notify(&d, &inbox, "Other", "https://example.test/m2", 3_000, false).await;

        let n = mark_notification_read(&d.node, &NoPush, &a, 5_000)
            .await
            .unwrap();
        assert_eq!(n, 2);
        for s in [&a, &b] {
            let r = d
                .store
                .get_resource(&Subject::from(s.as_str()))
                .await
                .unwrap();
            assert_eq!(r.get(READ_AT).unwrap().to_int().unwrap(), 5_000);
        }
        let list = list_notifications(&d.store, 10).await.unwrap();
        let find = |s: &str| list.iter().find(|n| n["subject"] == s).cloned();
        assert_eq!(find(&other).unwrap()["read"], false);
        assert_eq!(list.iter().filter(|n| n["read"] == true).count(), 1);

        // Again: nothing left to write.
        assert_eq!(
            mark_notification_read(&d.node, &NoPush, &a, 6_000)
                .await
                .unwrap(),
            0
        );
    }
}
