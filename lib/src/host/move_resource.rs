//! Moving a resource in the drive tree, as the web sidebar's drag and drop
//! does (`browser/data-browser/src/components/SideBar/useSidebarDnd.ts`).
//!
//! The web app has no children-order list on the parent. A drop writes the
//! dragged resource's own `parent` (only when it changes) and a fractional
//! `sortOrder` (midpoint of the two neighbours' keys, `prev + 1` at the end,
//! `next - 1` at the start). A key is the explicit `sortOrder`, else
//! `createdAt`; `lists::list_children` sorts by the same rule. One resource is
//! saved per move, so no sibling is renumbered.

use super::{
    lists::list_children,
    rows::row_resource,
    LocalWritePusher,
};
use crate::{
    errors::AtomicResult, runtime::AtomicNode, urls, Db, Resource, Storelike, Subject, Value,
};

/// The sort key of a resource: `sortOrder`, else `createdAt`.
fn sort_key(resource: &Resource) -> Option<f64> {
    let number = |v: &Value| match v {
        Value::Float(f) => Some(*f),
        Value::Integer(i) | Value::Timestamp(i) => Some(*i as f64),
        other => other.to_string().parse::<f64>().ok(),
    };
    resource
        .get(urls::SORT_ORDER)
        .ok()
        .and_then(number)
        .or_else(|| resource.get(urls::CREATED_AT).ok().and_then(number))
}

/// `computeSortOrder` of `browser/data-browser/src/helpers/fractionalSortOrder.ts`.
pub fn compute_sort_order(prev: Option<f64>, next: Option<f64>) -> f64 {
    match (prev, next) {
        (Some(p), Some(n)) => (p + n) / 2.0,
        (Some(p), None) => p + 1.0,
        (None, Some(n)) => n - 1.0,
        (None, None) => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as f64)
            .unwrap_or(0.0),
    }
}

/// Whether `ancestor` is `subject` or one of the parents above it.
async fn is_self_or_ancestor(store: &Db, ancestor: &str, subject: &str) -> bool {
    let target = crate::identifiers::canonicalize_scheme(ancestor);
    let mut current = subject.to_string();
    // Bounded, so a cycle already in the data cannot loop forever.
    for _ in 0..256 {
        if crate::identifiers::canonicalize_scheme(&current) == target {
            return true;
        }
        let Some(resource) = row_resource(store, &Subject::from(current.as_str())).await else {
            return false;
        };
        match resource.get(urls::PARENT) {
            Ok(p) => current = p.to_string(),
            Err(_) => return false,
        }
    }
    true
}

/// Move `subject` under `new_parent` at position `index` among the parent's
/// children as the sidebar lists them (`list_children`: the subject itself
/// left out, hidden folders skipped; an `index` past the end appends).
///
/// Refused: moving a resource into itself or one of its descendants, into a
/// resource whose children the sidebar does not unfold (tables, chat rooms,
/// ...), or moving a drive (it has no parent). Writes `parent` when it changes
/// and `sortOrder` always, signed by the device's agent and queued like every
/// local write. Does nothing when the resource already sits at `index`.
pub async fn move_resource(
    node: &AtomicNode,
    pusher: &dyn LocalWritePusher,
    subject: &str,
    new_parent: &str,
    index: usize,
) -> AtomicResult<()> {
    let store = node.db();
    let subject_id = Subject::from(subject);
    let mut resource = store.get_resource(&subject_id).await?;
    let old_parent = resource
        .get(urls::PARENT)
        .map(|v| v.to_string())
        .map_err(|_| "A drive cannot be moved")?;
    if is_self_or_ancestor(store, subject, new_parent).await {
        return Err("A resource cannot be moved into itself".into());
    }
    let parent_resource = row_resource(store, &Subject::from(new_parent))
        .await
        .ok_or("The new parent is not on this device")?;
    if super::lists::keeps_own_children(&parent_resource) {
        return Err("That resource does not hold children".into());
    }

    let listed = list_children(store, new_parent, usize::MAX / 2).await?;
    let siblings: Vec<String> = listed["children"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|r| r["subject"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let same = |a: &str, b: &str| {
        crate::identifiers::canonicalize_scheme(a) == crate::identifiers::canonicalize_scheme(b)
    };
    let current_position = siblings.iter().position(|s| same(s, subject));
    let others: Vec<&String> = siblings.iter().filter(|s| !same(s, subject)).collect();
    let index = index.min(others.len());

    if same(&old_parent, new_parent) && current_position == Some(index) {
        return Ok(());
    }

    let key_of = |s: &String| {
        let s = s.clone();
        async move {
            row_resource(store, &Subject::from(s.as_str()))
                .await
                .and_then(|r| sort_key(&r))
        }
    };
    let prev = match index.checked_sub(1) {
        Some(i) => key_of(others[i]).await,
        None => None,
    };
    let next = match others.get(index) {
        Some(s) => key_of(s).await,
        None => None,
    };
    let order = compute_sort_order(prev, next);

    if !same(&old_parent, new_parent) {
        resource.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(new_parent.into()))?;
    }
    resource.set_unsafe(urls::SORT_ORDER.into(), Value::Float(order))?;
    let response = node.save_locally(&mut resource).await?;
    pusher.push(&response).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{test_support::Device, NoPush};

    async fn folder(d: &Device, parent: &str, name: &str) -> String {
        d.store
            .create_resource(urls::FOLDER, parent, name, None)
            .await
            .unwrap()
    }

    async fn order(d: &Device, parent: &str) -> Vec<String> {
        let out = list_children(&d.store, parent, 100).await.unwrap();
        out["children"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["title"].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn a_resource_is_reordered_within_its_parent() {
        let d = Device::new().await;
        let _a = folder(&d, &d.drive, "A").await;
        let _b = folder(&d, &d.drive, "B").await;
        let c = folder(&d, &d.drive, "C").await;
        assert_eq!(order(&d, &d.drive).await, ["A", "B", "C"]);

        move_resource(&d.node, &NoPush, &c, &d.drive, 0)
            .await
            .unwrap();
        assert_eq!(order(&d, &d.drive).await, ["C", "A", "B"]);

        move_resource(&d.node, &NoPush, &c, &d.drive, 1)
            .await
            .unwrap();
        assert_eq!(order(&d, &d.drive).await, ["A", "C", "B"]);

        // Past the end appends.
        move_resource(&d.node, &NoPush, &c, &d.drive, 99)
            .await
            .unwrap();
        assert_eq!(order(&d, &d.drive).await, ["A", "B", "C"]);
        let r = d.store.get_resource(&c.as_str().into()).await.unwrap();
        assert_eq!(r.get(urls::PARENT).unwrap().to_string(), d.drive);
    }

    #[tokio::test]
    async fn a_resource_moves_to_another_parent_at_a_position() {
        let d = Device::new().await;
        let a = folder(&d, &d.drive, "A").await;
        let x = folder(&d, &a, "X").await;
        let _y = folder(&d, &a, "Y").await;
        let b = folder(&d, &d.drive, "B").await;

        move_resource(&d.node, &NoPush, &b, &a, 1).await.unwrap();
        assert_eq!(order(&d, &a).await, ["X", "B", "Y"]);
        assert_eq!(order(&d, &d.drive).await, ["A"]);

        move_resource(&d.node, &NoPush, &x, &d.drive, 0)
            .await
            .unwrap();
        assert_eq!(order(&d, &d.drive).await, ["X", "A"]);
        assert_eq!(order(&d, &a).await, ["B", "Y"]);
        let r = d.store.get_resource(&x.as_str().into()).await.unwrap();
        assert_eq!(r.get(urls::PARENT).unwrap().to_string(), d.drive);
    }

    #[tokio::test]
    async fn a_resource_cannot_move_into_itself_or_a_descendant() {
        let d = Device::new().await;
        let a = folder(&d, &d.drive, "A").await;
        let b = folder(&d, &a, "B").await;
        let c = folder(&d, &b, "C").await;

        assert!(move_resource(&d.node, &NoPush, &a, &a, 0).await.is_err());
        assert!(move_resource(&d.node, &NoPush, &a, &c, 0).await.is_err());
        assert!(move_resource(&d.node, &NoPush, &b, &c, 0).await.is_err());
        let r = d.store.get_resource(&a.as_str().into()).await.unwrap();
        assert_eq!(r.get(urls::PARENT).unwrap().to_string(), d.drive);
    }

    #[tokio::test]
    async fn tables_do_not_accept_children_and_a_drive_does_not_move() {
        let d = Device::new().await;
        let a = folder(&d, &d.drive, "A").await;
        let table = d
            .store
            .create_resource(urls::TABLE, &d.drive, "T", None)
            .await
            .unwrap();
        assert!(move_resource(&d.node, &NoPush, &a, &table, 0)
            .await
            .is_err());
        assert!(move_resource(&d.node, &NoPush, &d.drive, &a, 0)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn the_move_is_queued_and_pushed() {
        struct Count(std::sync::atomic::AtomicUsize);
        #[async_trait::async_trait]
        impl LocalWritePusher for Count {
            async fn push(&self, _: &crate::commit::CommitResponse) {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let d = Device::new().await;
        let a = folder(&d, &d.drive, "A").await;
        let b = folder(&d, &d.drive, "B").await;
        let pushed = Count(Default::default());
        move_resource(&d.node, &pushed, &b, &a, 0).await.unwrap();
        assert_eq!(pushed.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        // Already in place: nothing is written.
        move_resource(&d.node, &pushed, &b, &a, 0).await.unwrap();
        assert_eq!(pushed.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
