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

/// Last character in lexicographic ordering
const FINAL_CHAR: &str = "\u{ffff}";

#[tracing::instrument(skip(store))]
pub fn query_indexed(store: &Db, q: &crate::storelike::Query) -> AtomicResult<Option<QueryResult>> {
    let iter = if let Some(start) = &q.start_val {
        let start = create_collection_members_key(&q.into(), Some(start), None)?;
        let end = create_collection_members_key(&q.into(), Some(FINAL_CHAR), None)?;
        store.members_index.range(start..end)
    } else {
        let key = create_collection_members_key(&q.into(), None, None)?;
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
            let (k, _v) = kv.map_err(|_e| "Unable to parse query_cached")?;
            let (_q_filter, _val, subject) = parse_collection_members_key(&k)?;
            subjects.push(subject.into())
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
    let key = create_collection_members_key(collection, Some(&atom.value), Some(&atom.subject))?;
    if delete {
        store.members_index.remove(key)?;
    } else {
        store.members_index.insert(key, b"")?;
    }
    Ok(())
}

/// We can only store one bytearray as a key in Sled.
/// We separate the various items in it using this bit that's illegal in UTF-8.
const SEPARATION_BIT: u8 = 0xff;

const MAX_LEN: usize = 20;

/// Creates a key for a collection + value combination.
/// These are designed to be lexicographically sortable.
#[tracing::instrument()]
pub fn create_collection_members_key(
    collection: &QueryFilter,
    value: Option<&str>,
    subject: Option<&str>,
) -> AtomicResult<Vec<u8>> {
    let mut q_filter_bytes: Vec<u8> = bincode::serialize(collection)?;
    q_filter_bytes.push(SEPARATION_BIT);

    let mut value_bytes: Vec<u8> = if let Some(val) = value {
        let shorter = if val.len() > MAX_LEN {
            &val[0..MAX_LEN]
        } else {
            val
        };
        shorter.as_bytes().to_vec()
    } else {
        vec![]
    };
    value_bytes.push(SEPARATION_BIT);

    let subject_bytes = if let Some(sub) = subject {
        sub.as_bytes().to_vec()
    } else {
        vec![]
    };

    let bytesvec: Vec<u8> = [q_filter_bytes, value_bytes, subject_bytes].concat();
    Ok(bytesvec)
}

/// Creates a key for a collection + value combination.
/// These are designed to be lexicographically sortable.
#[tracing::instrument()]
pub fn parse_collection_members_key(bytes: &[u8]) -> AtomicResult<(QueryFilter, &str, &str)> {
    let mut iter = bytes.split(|b| b == &SEPARATION_BIT);
    let q_filter_bytes = iter.next().ok_or("No q_filter_bytes")?;
    let value_bytes = iter.next().ok_or("No value_bytes")?;
    let subject_bytes = iter.next().ok_or("No value_bytes")?;

    let q_filter: QueryFilter = bincode::deserialize(q_filter_bytes)?;
    let value = if !value_bytes.is_empty() {
        std::str::from_utf8(value_bytes).unwrap()
    } else {
        return Err("Can't parse value".into());
    };
    let subject = if !subject_bytes.is_empty() {
        std::str::from_utf8(subject_bytes).unwrap()
    } else {
        return Err("Can't parse subject".into());
    };
    Ok((q_filter, value, subject))
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    fn create_and_parse_key() {
        round_trip("\n", "\n");
        round_trip("short", "short");
        round_trip("12905.125.15", "12905.125.15");
        round_trip(
            "29NA(E*Tn3028nt87n_#T&*NF_AE*&#N@_T*&!#B_&*TN&*AEBT&*#B&TB@#!#@BB",
            "29NA(E*Tn3028nt87n_#",
        );

        fn round_trip(val: &str, val_check: &str) {
            let collection = QueryFilter {
                property: Some("http://example.org/prop".to_string()),
                value: Some("http://example.org/value".to_string()),
                sort_by: None,
            };
            let subject = "https://example.com/subject";
            let key = create_collection_members_key(&collection, Some(val), Some(subject)).unwrap();
            let (col, val_out, sub_out) = parse_collection_members_key(&key).unwrap();
            assert_eq!(col.property, collection.property);
            assert_eq!(val_check, val_out);
            assert_eq!(sub_out, subject);
        }
    }
}
