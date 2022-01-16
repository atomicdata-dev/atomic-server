//! The Collections Cache is used to speed up queries.
//! It sorts Members by their Value, so we can quickly paginate and sort.
//! It relies on lexicographic ordering of keys, which Sled utilizes using `scan_prefix` queries.

use crate::{
    errors::AtomicResult,
    storelike::{Query, QueryResult},
    Db, Storelike,
};
use serde::{Deserialize, Serialize};

/// Represents a filter on the Store.
/// A Value in the `watched_collections`.
/// These are used to check whether collections have to be updated when values have changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryFilter {
    /// Filtering by property URL
    pub property: Option<String>,
    /// Filtering by value
    pub value: Option<String>,
    /// The property by which the collection is sorted
    pub sort_by: Option<String>,
}

impl From<&Query> for QueryFilter {
    fn from(q: &Query) -> Self {
        QueryFilter {
            property: q.property.clone(),
            value: q.value.clone(),
            sort_by: q.sort_by.clone(),
        }
    }
}

/// Differs from a Regular Atom, since the value here is always a string,
/// and in the case of ResourceArrays, only a _single_ subject is used for each atom.
/// One IndexAtom for every member of the ResourceArray is created.
#[derive(Debug, Clone)]
pub struct IndexAtom {
    pub subject: String,
    pub property: String,
    pub value: String,
}

#[tracing::instrument(skip(store))]
pub fn query_indexed(store: &Db, q: &crate::storelike::Query) -> AtomicResult<Option<QueryResult>> {
    let iter = if let Some(start) = &q.start_val {
        let start = create_collection_members_key(&q.into(), start);
        let end = create_collection_members_key(&q.into(), "\u{ffff}");
        store.members_index.range(start.as_bytes()..end.as_bytes())
    } else {
        let key = create_collection_members_key(&q.into(), "");
        store.members_index.scan_prefix(key)
    };
    let mut subjects: Vec<String> = vec![];
    for (i, kv) in iter.enumerate() {
        if let Some(limit) = q.limit {
            if i >= limit {
                break;
            }
        }
        if i >= q.offset {
            let (_k, v) = kv.map_err(|_e| "Unable to parse query_cached")?;
            let subject = String::from_utf8(v.to_vec())?;
            subjects.push(subject)
        }
    }
    if subjects.is_empty() {
        return Ok(None);
    }
    let mut resources = Vec::new();
    if q.include_nested {
        for subject in &subjects {
            let resource = store.get_resource_extended(subject, true, q.for_agent.as_deref())?;
            resources.push(resource);
        }
    }
    Ok(Some((subjects, resources)))
}

#[tracing::instrument(skip(store))]
pub fn watch_collection(store: &Db, q_filter: &QueryFilter) -> AtomicResult<()> {
    store
        .watched_queries
        .insert(bincode::serialize(q_filter)?, b"")?;
    Ok(())
}

/// Initialize the index for Collections
// TODO: This is probably no the most reliable way of finding the collections to watch.
// I suppose we should add these dynamically when a Collection is being requested.
#[tracing::instrument(skip(store))]
pub fn create_watched_collections(store: &Db) -> AtomicResult<()> {
    let collections_url = format!("{}/collections", store.server_url);
    let collections_resource = store.get_resource_extended(&collections_url, false, None)?;
    for member_subject in collections_resource
        .get(crate::urls::COLLECTION_MEMBERS)?
        .to_subjects(None)?
    {
        let collection = store.get_resource_extended(&member_subject, false, None)?;
        let value = if let Ok(val) = collection.get(crate::urls::COLLECTION_VALUE) {
            Some(val.to_string())
        } else {
            None
        };
        let property = if let Ok(val) = collection.get(crate::urls::COLLECTION_PROPERTY) {
            Some(val.to_string())
        } else {
            None
        };
        let sort_by = if let Ok(val) = collection.get(crate::urls::COLLECTION_SORT_BY) {
            Some(val.to_string())
        } else {
            None
        };
        let q_filter = QueryFilter {
            property,
            value,
            sort_by,
        };
        watch_collection(store, &q_filter)?;
    }
    Ok(())
}

/// Check whether the Atom will be hit by a TPF query matching the Collections.
/// Updates the index accordingly.
#[tracing::instrument(skip(store))]
pub fn check_if_atom_matches_watched_collections(
    store: &Db,
    atom: &IndexAtom,
    delete: bool,
) -> AtomicResult<()> {
    for item in store.watched_queries.iter() {
        if let Ok((k, _v)) = item {
            let collection = bincode::deserialize::<QueryFilter>(&k)?;
            let should_update = match (&collection.property, &collection.value) {
                (Some(prop), Some(val)) => prop == &atom.property && val == &atom.value,
                (Some(prop), None) => prop == &atom.property,
                (None, Some(val)) => val == &atom.value,
                // We should not create indexes for Collections that iterate over _all_ resources.
                _ => false,
            };
            if should_update {
                update_member(store, &collection, atom, delete)?;
            }
        } else {
            return Err(format!("Can't deserialize collection index: {:?}", item).into());
        }
    }
    Ok(())
}

/// Adds or removes a single item (IndexAtom) to the index_members cache.
#[tracing::instrument(skip(store))]
pub fn update_member(
    store: &Db,
    collection: &QueryFilter,
    atom: &IndexAtom,
    delete: bool,
) -> AtomicResult<()> {
    let key = create_collection_members_key(collection, &atom.value);

    // TODO: Remove .unwraps()
    if delete {
        let remove = |old: Option<&[u8]>| -> Option<Vec<u8>> {
            if let Some(bytes) = old {
                let subjects: Vec<String> = bincode::deserialize(bytes).unwrap();

                let filtered: Vec<String> = subjects
                    .into_iter()
                    .filter(|x| x == &atom.subject)
                    .collect();

                let bytes = bincode::serialize(&filtered).unwrap();
                Some(bytes)
            } else {
                None
            }
        };
        store.members_index.update_and_fetch(key, remove)?;
    } else {
        let append = |old: Option<&[u8]>| -> Option<Vec<u8>> {
            let mut subjects: Vec<String> = if let Some(bytes) = old {
                bincode::deserialize(bytes).unwrap()
            } else {
                vec![]
            };
            if !subjects.contains(&atom.subject) {
                subjects.push(atom.subject.clone());
            }
            let bytes = bincode::serialize(&subjects).unwrap();
            Some(bytes)
        };
        store.members_index.update_and_fetch(key, append)?;
    };

    Ok(())
}

/// Creates a key for a collection + value combination.
/// These are designed to be lexicographically sortable.
#[tracing::instrument()]
pub fn create_collection_members_key(collection: &QueryFilter, value: &str) -> String {
    let col_str = serde_json::to_string(collection).unwrap();
    format!("{}\n{}", col_str, value)
}
