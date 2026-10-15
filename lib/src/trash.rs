//! Trash: park a resource in the drive's Trash folder instead of destroying it.
//!
//! Mirrors `browser/lib/src/trash.ts`. The drive points at its Trash folder
//! through [`urls::TRASH_FOLDER`]; trashing reparents a resource under that
//! folder and remembers the old parent in [`urls::TRASHED_FROM`] so
//! [`restore`] can put it back. Nothing is destroyed.
//!
//! "Trashed" is a fact about the parent chain, not a flag: a resource is
//! trashed when its direct parent is the Trash folder, and (with `deep`) when
//! any ancestor is. Search and collections hide such resources by default;
//! see [`crate::search`] and [`crate::collections`].

use std::collections::{HashMap, HashSet};

use crate::{
    errors::{AtomicErrorType, AtomicResult},
    property_identity::is_property_id,
    storelike::Query,
    urls, Db, Resource, Storelike, Subject, Value,
};

/// Name of the folder created for a drive's Trash.
pub const TRASH_FOLDER_NAME: &str = "Trash";

/// Longest ancestor chain followed. Parent cycles end earlier (visited set).
pub const MAX_TRASH_DEPTH: usize = 64;

fn pure(subject: &str) -> String {
    Subject::from(subject).pure_id()
}

fn parent_of(resource: &Resource) -> Option<String> {
    resource
        .get(urls::PARENT)
        .ok()
        .map(|v| pure(&v.to_string()))
}

/// The drive's Trash folder, if one was ever created.
pub fn read_trash_folder(drive: &Resource) -> Option<String> {
    drive
        .get(urls::TRASH_FOLDER)
        .ok()
        .map(|v| v.to_string())
        .filter(|s| !s.is_empty())
}

/// The drive's Trash folder as far as the local store knows. Never creates
/// one and never fetches.
pub fn peek_trash_folder(store: &Db, drive: &str) -> Option<String> {
    let drive = store.get_resource_shallow(&Subject::from(drive)).ok()?;
    read_trash_folder(&drive)
}

/// The drive's Trash folder, created on first use. A pointer to a folder that
/// no longer exists is stale and is overwritten; any other read failure is
/// returned, so a real folder is never orphaned by a transient error.
pub async fn get_or_create_trash_folder(store: &Db, drive: &str) -> AtomicResult<String> {
    let mut drive_resource = store.get_resource(&Subject::from(drive)).await?;

    if let Some(existing) = read_trash_folder(&drive_resource) {
        match store.get_resource(&Subject::from(existing.as_str())).await {
            Ok(_) => return Ok(existing),
            Err(e) if e.error_type == AtomicErrorType::NotFoundError => {}
            Err(e) => return Err(e),
        }
    }

    let trash = store
        .create_resource(urls::FOLDER, drive, TRASH_FOLDER_NAME, None)
        .await?;
    drive_resource.set_unsafe(
        urls::TRASH_FOLDER.into(),
        Value::AtomicUrl(trash.as_str().into()),
    )?;
    drive_resource.save(store).await?;

    Ok(trash)
}

/// Reparents `resource` under `trash` and remembers the old parent. Does not
/// save. False (and no change) when `resource` is the Trash folder or already
/// sits directly in it.
pub fn apply_trash(resource: &mut Resource, trash: &str) -> AtomicResult<bool> {
    let trash = pure(trash);
    let parent = resource.get(urls::PARENT).ok().map(|v| v.to_string());

    if pure(resource.get_subject().as_str()) == trash
        || parent.as_deref().is_some_and(|p| pure(p) == trash)
    {
        return Ok(false);
    }

    if let Some(parent) = parent {
        resource.set_unsafe(
            urls::TRASHED_FROM.into(),
            Value::AtomicUrl(parent.as_str().into()),
        )?;
    }
    resource.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(trash.as_str().into()))?;

    Ok(true)
}

/// Moves `resource` to `target` and forgets where it was trashed from. Does
/// not save.
pub fn apply_restore(resource: &mut Resource, target: &str) -> AtomicResult<()> {
    resource.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(target.into()))?;
    if resource.get(urls::TRASHED_FROM).is_ok() {
        resource.remove_propval(urls::TRASHED_FROM)?;
    }
    Ok(())
}

/// Parks a resource in the drive's Trash folder (created on first use) and
/// remembers where it came from so [`restore`] can put it back. Nothing is
/// destroyed. Returns false when there was nothing to do (the Trash folder
/// itself, the drive itself, or an item already directly in the Trash).
/// A content-addressed property cannot be trashed: its parent is part of its ID.
pub async fn trash(store: &Db, subject: &str, drive: &str) -> AtomicResult<bool> {
    if is_property_id(subject) {
        return Err("A property can't be moved to the trash.".into());
    }
    // The drive has no parent to leave and must not end up below itself.
    if pure(subject) == pure(drive) {
        return Ok(false);
    }

    let trash = get_or_create_trash_folder(store, drive).await?;
    let mut resource = store.get_resource(&Subject::from(subject)).await?;

    if !apply_trash(&mut resource, &trash)? {
        return Ok(false);
    }
    resource.save(store).await?;

    Ok(true)
}

/// Moves a trashed resource back to the parent it came from. Falls back to the
/// drive root when that parent is gone (destroyed or unreadable).
pub async fn restore(store: &Db, subject: &str, drive: &str) -> AtomicResult<()> {
    let mut resource = store.get_resource(&Subject::from(subject)).await?;
    let from = resource.get(urls::TRASHED_FROM).ok().map(|v| v.to_string());
    let mut target = drive.to_string();

    if let Some(from) = from {
        if store
            .get_resource(&Subject::from(from.as_str()))
            .await
            .is_ok()
        {
            target = from;
        }
    }

    apply_restore(&mut resource, &target)?;
    resource.save(store).await?;

    Ok(())
}

/// Whether the resource sits directly in the drive's Trash folder. With
/// `deep`, also when any ancestor does. A visited set ends parent cycles and
/// the walk stops after [`MAX_TRASH_DEPTH`] ancestors.
pub fn is_trashed(store: &Db, resource: &Resource, drive: &str, deep: bool) -> bool {
    let mut lookup = TrashLookup::new(store);
    let Some(trash) = lookup.trash_of_drive(drive) else {
        return false;
    };
    lookup.parent_in_trash(resource, &trash, deep)
}

/// [`is_trashed`] for a subject. A subject that cannot be read is not trashed.
pub fn is_subject_trashed(store: &Db, subject: &str, drive: &str, deep: bool) -> bool {
    store
        .get_resource_shallow(&Subject::from(subject))
        .is_ok_and(|resource| is_trashed(store, &resource, drive, deep))
}

/// Answers "is this trashed?" many times, remembering each drive's Trash
/// folder and the verdict for every ancestor it walked, so siblings share the
/// walk. Reads materialized rows only (`get_resource_shallow`).
pub(crate) struct TrashLookup<'a> {
    store: &'a Db,
    /// Drive (pure id) -> its Trash folder (pure id).
    drive_trash: HashMap<String, Option<String>>,
    /// Ancestor (pure id) -> whether its chain reaches the Trash.
    ancestors: HashMap<String, bool>,
}

impl<'a> TrashLookup<'a> {
    pub(crate) fn new(store: &'a Db) -> Self {
        Self {
            store,
            drive_trash: HashMap::new(),
            ancestors: HashMap::new(),
        }
    }

    pub(crate) fn trash_of_drive(&mut self, drive: &str) -> Option<String> {
        let key = pure(drive);
        if let Some(known) = self.drive_trash.get(&key) {
            return known.clone();
        }
        let trash = self
            .store
            .get_resource_shallow(&Subject::from(key.as_str()))
            .ok()
            .and_then(|d| read_trash_folder(&d))
            .map(|t| pure(&t));
        self.drive_trash.insert(key, trash.clone());
        trash
    }

    /// Whether the resource is in the Trash of its own drive (deep).
    pub(crate) fn is_hidden_member(&mut self, resource: &Resource) -> bool {
        let Some(drive) = resource.get_drive() else {
            return false;
        };
        match self.trash_of_drive(drive.as_str()) {
            Some(trash) => self.parent_in_trash(resource, &trash, true),
            None => false,
        }
    }

    /// Whether `subject` is the Trash folder of its drive, or sits in it.
    fn is_trash_or_inside(&mut self, subject: &str) -> bool {
        let Ok(resource) = self.store.get_resource_shallow(&Subject::from(subject)) else {
            return false;
        };
        let Some(drive) = resource.get_drive() else {
            return false;
        };
        let Some(trash) = self.trash_of_drive(drive.as_str()) else {
            return false;
        };
        pure(subject) == trash || self.parent_in_trash(&resource, &trash, true)
    }

    fn parent_in_trash(&mut self, resource: &Resource, trash: &str, deep: bool) -> bool {
        let origin = pure(resource.get_subject().as_str());
        let Some(start) = parent_of(resource) else {
            return false;
        };
        let mut visited: HashSet<String> = HashSet::from([origin]);
        let mut path: Vec<String> = Vec::new();
        let mut current = start;
        let mut verdict = false;

        for _ in 0..MAX_TRASH_DEPTH {
            if current == trash {
                verdict = true;
                break;
            }
            if !deep {
                break;
            }
            if let Some(known) = self.ancestors.get(&current) {
                verdict = *known;
                break;
            }
            if !visited.insert(current.clone()) {
                break;
            }
            path.push(current.clone());
            let next = self
                .store
                .get_resource_shallow(&Subject::from(current.as_str()))
                .ok()
                .and_then(|r| parent_of(&r));
            match next {
                Some(next) => current = next,
                None => break,
            }
        }

        if deep {
            for node in path {
                self.ancestors.insert(node, verdict);
            }
        }
        verdict
    }
}

/// The per-query filter behind [`Query::exclude_trashed`]. `None` when the
/// query hides nothing: it does not exclude the Trash, or it explicitly lists
/// the children of the Trash folder (or of something inside it), which is the
/// Trash view itself.
pub(crate) fn filter_for_query<'a>(store: &'a Db, q: &Query) -> Option<TrashLookup<'a>> {
    if !q.exclude_trashed {
        return None;
    }
    let mut lookup = TrashLookup::new(store);

    let listed_parents = q
        .property
        .iter()
        .zip(q.value.iter())
        .map(|(p, v)| (p.as_str(), v))
        .chain(q.filters.iter().filter_map(|f| {
            (f.operator == crate::storelike::FilterOperator::Equal)
                .then(|| f.property.as_deref().zip(f.value.as_ref()))
                .flatten()
        }))
        .filter(|(p, _)| *p == urls::PARENT)
        .map(|(_, v)| v.to_string());

    for parent in listed_parents {
        if lookup.is_trash_or_inside(&parent) {
            return None;
        }
    }

    Some(lookup)
}

#[cfg(test)]
mod tests;
