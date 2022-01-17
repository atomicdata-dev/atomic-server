//! The Collections Cache is used to speed up queries.
//! It sorts Members by their Value, so we can quickly paginate and sort.
//! It relies on lexicographic ordering of keys, which Sled utilizes using `scan_prefix` queries.

use crate::{
    errors::AtomicResult,
    storelike::{Query, QueryResult},
    Atom, Db, Storelike,
};
use serde::{Deserialize, Serialize};

/// A subset of a full [Query].
/// Represents a sorted filter on the Store.
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
pub const FIRST_CHAR: &str = "\u{0000}";
pub const END_CHAR: &str = "\u{ffff}";

#[tracing::instrument(skip(store))]
/// Performs a query on the `members_index` Tree, which is a lexicographic sorted list of all hits for QueryFilters.
pub fn query_indexed(store: &Db, q: &Query) -> AtomicResult<Option<QueryResult>> {
    let start = if let Some(val) = &q.start_val {
        val
    } else {
        FIRST_CHAR
    };
    let end = if let Some(val) = &q.end_val {
        val
    } else {
        END_CHAR
    };
    let start_key = create_collection_members_key(&q.into(), Some(start), None)?;
    let end_key = create_collection_members_key(&q.into(), Some(end), None)?;

    let iter: Box<dyn Iterator<Item = std::result::Result<(sled::IVec, sled::IVec), sled::Error>>> =
        if q.sort_desc {
            Box::new(store.members_index.range(start_key..end_key).rev())
        } else {
            Box::new(store.members_index.range(start_key..end_key))
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

/// Adss atoms for a specific query to the index
pub fn add_atoms_to_index(store: &Db, atoms: &[Atom], q_filter: &QueryFilter) -> AtomicResult<()> {
    // Add all atoms to the index, so next time we do get a cache hit.
    for atom in atoms {
        let index_atom = IndexAtom {
            subject: atom.subject.clone(),
            property: atom.subject.clone(),
            value: atom.value.to_string(),
        };
        update_member(store, q_filter, &index_atom, false)?;
    }
    Ok(())
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

/// Maximum string length for values in the members_index. Should be long enough to contain pretty long URLs, but not very long documents.
pub const MAX_LEN: usize = 120;

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
        let lowercase = shorter.to_lowercase();
        lowercase.as_bytes().to_vec()
    } else {
        vec![0]
    };
    value_bytes.push(SEPARATION_BIT);

    let subject_bytes = if let Some(sub) = subject {
        sub.as_bytes().to_vec()
    } else {
        vec![0]
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
        std::str::from_utf8(value_bytes)
            .map_err(|e| format!("Can't parse value in members_key: {}", e))?
    } else {
        return Err("Can't parse value in members_key".into());
    };
    let subject = if !subject_bytes.is_empty() {
        std::str::from_utf8(subject_bytes)
            .map_err(|e| format!("Can't parse subject in members_key: {}", e))?
    } else {
        return Err("Can't parse subject in members_key".into());
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
        round_trip("UP", "up");
        round_trip("12905.125.15", "12905.125.15");
        round_trip(
            "29NA(E*Tn3028nt87n_#T&*NF_AE*&#N@_T*&!#B_&*TN&*AEBT&*#B&TB@#!#@BB29NA(E*Tn3028nt87n_#T&*NF_AE*&#N@_T*&!#B_&*TN&*AEBT&*#B&TB@#!#@BB29NA(E*Tn3028nt87n_#T&*NF_AE*&#N@_T*&!#B_&*TN&*AEBT&*#B&TB@#!#@BB29NA(E*Tn3028nt87n_#T&*NF_AE*&#N@_T*&!#B_&*TN&*AEBT&*#B&TB@#!#@BB29NA(E*Tn3028nt87n_#T&*NF_AE*&#N@_T*&!#B_&*TN&*AEBT&*#B&TB@#!#@BB29NA(E*Tn3028nt87n_#T&*NF_AE*&#N@_T*&!#B_&*TN&*AEBT&*#B&TB@#!#@BB29NA(E*Tn3028nt87n_#T&*NF_AE*&#N@_T*&!#B_&*TN&*AEBT&*#B&TB@#!#@BB29NA(E*Tn3028nt87n_#T&*NF_AE*&#N@_T*&!#B_&*TN&*AEBT&*#B&TB@#!#@BB",
            "29na(e*tn3028nt87n_#t&*nf_ae*&#n@_t*&!#b_&*tn&*aebt&*#b&tb@#!#@bb29na(e*tn3028nt87n_#t&*nf_ae*&#n@_t*&!#b_&*tn&*aebt&*#b",
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

    #[test]
    fn lexicographic_partial() {
        let q = QueryFilter {
            property: Some("http://example.org/prop".to_string()),
            value: Some("http://example.org/value".to_string()),
            sort_by: None,
        };

        let start_none = create_collection_members_key(&q, None, None).unwrap();
        let start_str = create_collection_members_key(&q, Some("a"), None).unwrap();
        let a_downcase = create_collection_members_key(&q, Some("a"), Some("wadiaodn")).unwrap();
        let b_upcase = create_collection_members_key(&q, Some("B"), Some("wadiaodn")).unwrap();
        let mid3 = create_collection_members_key(&q, Some("hi there"), Some("egnsoinge")).unwrap();
        let end = create_collection_members_key(&q, Some(END_CHAR), None).unwrap();

        assert!(start_none < start_str);
        assert!(start_str < a_downcase);
        assert!(a_downcase < b_upcase);
        assert!(b_upcase < mid3);
        assert!(mid3 < end);

        let mut sorted = vec![&end, &start_str, &a_downcase, &b_upcase, &start_none];
        sorted.sort();

        let expected = vec![&start_none, &start_str, &a_downcase, &b_upcase, &end];

        assert_eq!(sorted, expected);
    }
}
