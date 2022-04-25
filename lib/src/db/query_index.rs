//! The Collections Cache is used to speed up queries.
//! It sorts Members by their Value, so we can quickly paginate and sort.
//! It relies on lexicographic ordering of keys, which Sled utilizes using `scan_prefix` queries.

use crate::{
    errors::AtomicResult,
    storelike::{Query, QueryResult},
    values::query_value_compare,
    Atom, Db, Resource, Storelike, Value,
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
    pub value: Option<Value>,
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
pub fn query_indexed(store: &Db, q: &Query) -> AtomicResult<QueryResult> {
    // When there is no explicit start / end value passed, we use the very first and last
    // lexicographic characters in existence to make the range practically encompass all values.
    let start = if let Some(val) = &q.start_val {
        val.clone()
    } else {
        Value::String(FIRST_CHAR.into())
    };
    let end = if let Some(val) = &q.end_val {
        val.clone()
    } else {
        Value::String(END_CHAR.into())
    };
    let start_key = create_query_index_key(&q.into(), Some(&start), None)?;
    let end_key = create_query_index_key(&q.into(), Some(&end), None)?;

    let iter: Box<dyn Iterator<Item = std::result::Result<(sled::IVec, sled::IVec), sled::Error>>> =
        if q.sort_desc {
            Box::new(store.members_index.range(start_key..end_key).rev())
        } else {
            Box::new(store.members_index.range(start_key..end_key))
        };

    let mut subjects: Vec<String> = vec![];
    let mut resources = Vec::new();
    let mut count = 0;

    let self_url = store
        .get_self_url()
        .ok_or("No self_url set, required for Queries")?;

    let limit = if let Some(limit) = q.limit {
        limit
    } else {
        std::usize::MAX
    };

    for (i, kv) in iter.enumerate() {
        // The user's maximum amount of results has not yet been reached
        // and
        // The users minimum starting distance (offset) has been reached
        let in_selection = subjects.len() < limit && i >= q.offset;
        if in_selection {
            let (k, _v) = kv.map_err(|_e| "Unable to parse query_cached")?;
            let (_q_filter, _val, subject) = parse_collection_members_key(&k)?;

            // If no external resources should be included, skip this one if it's an external resource
            if !q.include_external && !subject.starts_with(&self_url) {
                continue;
            }

            // When an agent is defined, we must perform authorization checks
            // WARNING: EXPENSIVE!
            // TODO: Make async
            if q.include_nested || q.for_agent.is_some() {
                match store.get_resource_extended(subject, true, q.for_agent.as_deref()) {
                    Ok(resource) => {
                        resources.push(resource);
                        subjects.push(subject.into())
                    }
                    Err(e) => match e.error_type {
                        crate::AtomicErrorType::NotFoundError => {}
                        crate::AtomicErrorType::UnauthorizedError => {}
                        crate::AtomicErrorType::OtherError => {
                            return Err(
                                format!("Error when getting resource in collection: {}", e).into()
                            )
                        }
                    },
                }
            } else {
                // If there is no need for nested resources, and no auth checks, we can skip the expensive part!
                subjects.push(subject.into())
            }
        }
        // We iterate over every single resource, even if we don't perform any computation on the items.
        // This helps with pagination, but it comes at a serious performance cost. We might need to change how this works later on.
        // Also, this count does not take into account the `include_external` filter.
        // https://github.com/joepio/atomic-data-rust/issues/290
        count = i + 1;
    }

    Ok(QueryResult {
        count,
        resources,
        subjects,
    })
}

#[tracing::instrument(skip(store))]
/// Adds a QueryFilter to the `watched_queries`
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
            // TODO: check the datatype. Now we assume it's a string
            Some(val.clone())
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

/// Checks if the resource will match with a QueryFilter.
/// Does any value or property or sort value match?
/// Returns the matching property, if found.
/// E.g. if a Resource
fn check_resource_query_filter_property(
    resource: &Resource,
    q_filter: &QueryFilter,
) -> Option<String> {
    if let Some(property) = &q_filter.property {
        if let Ok(matched_propval) = resource.get(property) {
            if let Some(filter_val) = &q_filter.value {
                if matched_propval.to_string() == filter_val.to_string() {
                    return Some(property.to_string());
                }
            } else {
                return Some(property.to_string());
            }
        }
    } else if let Some(filter_val) = &q_filter.value {
        for (prop, val) in resource.get_propvals() {
            if query_value_compare(val, filter_val) {
                return Some(prop.to_string());
            }
        }
        return None;
    }
    None
}

/// Checks if a new IndexAtom should be updated for a specific [QueryFilter]
/// It's only true if the [Resource] is matched by the [QueryFilter], and the [Value] is relevant for the index.
/// This also sometimes updates other keys, for in the case one changed Atom influences other Indexed Members.
/// See https://github.com/joepio/atomic-data-rust/issues/395
// This is probably the most complex function in the whole repo.
// If things go wrong when making changes, add a test and fix stuff in the logic below.
pub fn should_update(
    q_filter: &QueryFilter,
    index_atom: &IndexAtom,
    resource: &Resource,
    delete: bool,
    store: &Db,
) -> AtomicResult<bool> {
    let resource_check = check_resource_query_filter_property(resource, q_filter);
    let matching_prop = if let Some(p) = resource_check {
        p
    } else {
        return Ok(false);
    };

    if let Some(sort_prop) = &q_filter.sort_by {
        // Sometimes, a removed atom should also invalidate other IndexAtoms, because the QueryFilter no longer matches.
        // This only happens when there is a `sort_by` in the QueryFilter.
        // We then make sure to also update the sort_by value.
        if let Ok(sorted_val) = resource.get(sort_prop) {
            update_indexed_member(store, q_filter, &index_atom.subject, sorted_val, delete)?;
        }
    }

    let should: bool = match (&q_filter.property, &q_filter.value, &q_filter.sort_by) {
        // Whenever the atom matches with either the sorted or the filtered prop, we have to update
        (Some(filterprop), Some(filter_val), Some(sortprop)) => {
            if sortprop == &index_atom.property {
                // Update the Key, which contains the sorted value
                return Ok(true);
            }
            if filterprop == &index_atom.property && index_atom.value == filter_val.to_string() {
                return Ok(true);
            }
            // If either one of these match
            let relevant_prop =
                filterprop == &index_atom.property || sortprop == &index_atom.property;
            // And the value matches, we have to update
            relevant_prop && filter_val.to_string() == index_atom.value
        }
        (Some(filter_prop), Some(_filter_val), None) => filter_prop == &index_atom.property,
        (Some(filter_prop), None, Some(sort_by)) => {
            filter_prop == &index_atom.property || sort_by == &index_atom.property
        }
        (Some(filter_prop), None, None) => filter_prop == &index_atom.property,
        (None, Some(filter_val), None) => {
            filter_val.to_string() == index_atom.value || matching_prop == index_atom.property
        }
        (None, Some(filter_val), Some(sort_by)) => {
            filter_val.to_string() == index_atom.value
                || matching_prop == index_atom.property
                || &matching_prop == sort_by
                || &index_atom.property == sort_by
        }
        // We should not create indexes for Collections that iterate over _all_ resources.
        (a, b, c) => todo!("This query filter is not supported yet! Please create an issue on Github for filter {:?} {:?} {:?}", a, b, c),
    };
    Ok(should)
}

/// This is called when an atom is added or deleted.
/// Check whether the Atom will be hit by a TPF query matching the [QueryFilter].
/// Updates the index accordingly.
/// We need both the `index_atom` and the full `atom`.
#[tracing::instrument(skip_all)]
pub fn check_if_atom_matches_watched_query_filters(
    store: &Db,
    index_atom: &IndexAtom,
    atom: &Atom,
    delete: bool,
    resource: &Resource,
) -> AtomicResult<()> {
    for query in store.watched_queries.iter() {
        // The keys store all the data
        if let Ok((k, _v)) = query {
            let q_filter = bincode::deserialize::<QueryFilter>(&k)
                .map_err(|e| format!("Could not deserialize QueryFilter: {}", e))?;

            if should_update(&q_filter, index_atom, resource, delete, store)? {
                update_indexed_member(store, &q_filter, &atom.subject, &atom.value, delete)?;
            }
        } else {
            return Err(format!("Can't deserialize collection index: {:?}", query).into());
        }
    }
    Ok(())
}

/// Adds or removes a single item (IndexAtom) to the index_members cache.
#[tracing::instrument(skip(store))]
pub fn update_indexed_member(
    store: &Db,
    collection: &QueryFilter,
    subject: &str,
    value: &Value,
    delete: bool,
) -> AtomicResult<()> {
    let key = create_query_index_key(
        collection,
        // Maybe here we should serialize the value a bit different - as a sortable string, where Arrays are sorted by their length.
        Some(value),
        Some(subject),
    )?;
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
pub fn create_query_index_key(
    query_filter: &QueryFilter,
    value: Option<&Value>,
    subject: Option<&str>,
) -> AtomicResult<Vec<u8>> {
    let mut q_filter_bytes: Vec<u8> = bincode::serialize(query_filter)?;
    q_filter_bytes.push(SEPARATION_BIT);

    let mut value_bytes: Vec<u8> = if let Some(val) = value {
        let val_string = val.to_sortable_string();
        let shorter = if val_string.len() > MAX_LEN {
            &val_string[0..MAX_LEN]
        } else {
            &val_string
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

/// Converts one Value to a bunch of indexable items.
/// Returns None for unsupported types.
pub fn value_to_reference_index_string(value: &Value) -> Option<Vec<String>> {
    let vals = match value {
        // This results in wrong indexing, as some subjects will be numbers.
        Value::ResourceArray(_v) => value.to_subjects(None).unwrap_or_else(|_| vec![]),
        Value::AtomicUrl(v) => vec![v.into()],
        // We don't index nested resources for now
        Value::Resource(_r) => return None,
        Value::NestedResource(_r) => return None,
        // This might result in unnecessarily long strings, sometimes. We may want to shorten them later.
        val => vec![val.to_string()],
    };
    Some(vals)
}

/// Converts one Atom to a series of stringified values that can be indexed.
#[tracing::instrument(skip(atom))]
pub fn atom_to_indexable_atoms(atom: &Atom) -> AtomicResult<Vec<IndexAtom>> {
    let index_atoms = match value_to_reference_index_string(&atom.value) {
        Some(v) => v,
        None => return Ok(vec![]),
    };
    let index_atoms = index_atoms
        .into_iter()
        .map(|v| IndexAtom {
            value: v,
            subject: atom.subject.clone(),
            property: atom.property.clone(),
        })
        .collect();
    Ok(index_atoms)
}

#[cfg(test)]
pub mod test {
    use crate::urls;

    use super::*;

    #[test]
    fn create_and_parse_key() {
        round_trip_same(Value::String("\n".into()));
        round_trip_same(Value::String("short".into()));
        round_trip_same(Value::Float(1.142));
        round_trip_same(Value::Float(-1.142));
        round_trip(
            &Value::String("UPPERCASE".into()),
            &Value::String("uppercase".into()),
        );
        round_trip(&Value::String("29NA(E*Tn3028nt87n_#T&*NF_AE*&#N@_T*&!#B_&*TN&*AEBT&*#B&TB@#!#@BB29NA(E*Tn3028nt87n_#T&*NF_AE*&#N@_T*&!#B_&*TN&*AEBT&*#B&TB@#!#@BB29NA(E*Tn3028nt87n_#T&*NF_AE*&#N@_T*&!#B_&*TN&*AEBT&*#B&TB@#!#@BB29NA(E*Tn3028nt87n_#T&*NF_AE*&#N@_T*&!#B_&*TN&*AEBT&*#B&TB@#!#@BB29NA(E*Tn3028nt87n_#T&*NF_AE*&#N@_T*&!#B_&*TN&*AEBT&*#B&TB@#!#@BB29NA(E*Tn3028nt87n_#T&*NF_AE*&#N@_T*&!#B_&*TN&*AEBT&*#B&TB@#!#@BB29NA(E*Tn3028nt87n_#T&*NF_AE*&#N@_T*&!#B_&*TN&*AEBT&*#B&TB@#!#@BB29NA(E*Tn3028nt87n_#T&*NF_AE*&#N@_T*&!#B_&*TN&*AEBT&*#B&TB@#!#@BB".into()), &Value::String("29na(e*tn3028nt87n_#t&*nf_ae*&#n@_t*&!#b_&*tn&*aebt&*#b&tb@#!#@bb29na(e*tn3028nt87n_#t&*nf_ae*&#n@_t*&!#b_&*tn&*aebt&*#b".into()));

        fn round_trip_same(val: Value) {
            round_trip(&val, &val)
        }

        fn round_trip(val: &Value, val_check: &Value) {
            let collection = QueryFilter {
                property: Some("http://example.org/prop".to_string()),
                value: Some(Value::AtomicUrl("http://example.org/value".to_string())),
                sort_by: None,
            };
            let subject = "https://example.com/subject";
            let key = create_query_index_key(&collection, Some(val), Some(subject)).unwrap();
            let (col, val_out, sub_out) = parse_collection_members_key(&key).unwrap();
            assert_eq!(col.property, collection.property);
            assert_eq!(val_check.to_string(), val_out);
            assert_eq!(sub_out, subject);
        }
    }

    #[test]
    fn lexicographic_partial() {
        let q = QueryFilter {
            property: Some("http://example.org/prop".to_string()),
            value: Some(Value::AtomicUrl("http://example.org/value".to_string())),
            sort_by: None,
        };

        let start_none = create_query_index_key(&q, None, None).unwrap();
        let num_1 = create_query_index_key(&q, Some(&Value::Float(1.0)), None).unwrap();
        let num_2 = create_query_index_key(&q, Some(&Value::Float(2.0)), None).unwrap();
        // let num_10 = create_query_index_key(&q, Some(&Value::Float(10.0)), None).unwrap();
        let num_1000 = create_query_index_key(&q, Some(&Value::Float(1000.0)), None).unwrap();
        let start_str = create_query_index_key(&q, Some(&Value::String("1".into())), None).unwrap();
        let a_downcase =
            create_query_index_key(&q, Some(&Value::String("a".into())), None).unwrap();
        let b_upcase = create_query_index_key(&q, Some(&Value::String("B".into())), None).unwrap();
        let mid3 =
            create_query_index_key(&q, Some(&Value::String("hi there".into())), None).unwrap();
        let end = create_query_index_key(&q, Some(&Value::String(END_CHAR.into())), None).unwrap();

        assert!(start_none < num_1);
        assert!(num_1 < num_2);
        // TODO: Fix sorting numbers
        // https://github.com/joepio/atomic-data-rust/issues/287
        // assert!(num_2 < num_10);
        // assert!(num_10 < num_1000);
        assert!(num_1000 < a_downcase);
        assert!(a_downcase < b_upcase);
        assert!(b_upcase < mid3);
        assert!(mid3 < end);

        let mut sorted = vec![&end, &start_str, &a_downcase, &b_upcase, &start_none];
        sorted.sort();

        let expected = vec![&start_none, &start_str, &a_downcase, &b_upcase, &end];

        assert_eq!(sorted, expected);
    }

    #[test]
    fn should_update_or_not() {
        let store = &Db::init_temp("should_update_or_not").unwrap();

        let prop = urls::IS_A.to_string();
        let class = urls::AGENT;

        let qf_prop_val = QueryFilter {
            property: Some(prop.clone()),
            value: Some(Value::AtomicUrl(class.to_string())),
            sort_by: None,
        };

        let qf_prop = QueryFilter {
            property: Some(prop.clone()),
            value: None,
            sort_by: None,
        };

        let qf_val = QueryFilter {
            property: None,
            value: Some(Value::AtomicUrl(class.to_string())),
            sort_by: None,
        };

        let resource_correct_class = Resource::new_instance(class, store).unwrap();

        let subject: String = "https://example.com/someAgent".into();

        let index_atom = IndexAtom {
            subject,
            property: prop.clone(),
            value: class.to_string(),
        };

        // We should be able to find the resource by propval, val, and / or prop.
        assert!(
            should_update(&qf_val, &index_atom, &resource_correct_class, false, store).unwrap()
        );
        assert!(should_update(
            &qf_prop_val,
            &index_atom,
            &resource_correct_class,
            false,
            store
        )
        .unwrap());
        assert!(
            should_update(&qf_prop, &index_atom, &resource_correct_class, false, store).unwrap()
        );

        // Test when a different value is passed
        let resource_wrong_class = Resource::new_instance(urls::PARAGRAPH, store).unwrap();
        assert!(should_update(&qf_prop, &index_atom, &resource_wrong_class, false, store).unwrap());
        assert!(!should_update(&qf_val, &index_atom, &resource_wrong_class, false, store).unwrap());
        assert!(!should_update(
            &qf_prop_val,
            &index_atom,
            &resource_wrong_class,
            false,
            store
        )
        .unwrap());

        let qf_prop_val_sort = QueryFilter {
            property: Some(prop.clone()),
            value: Some(Value::AtomicUrl(class.to_string())),
            sort_by: Some(urls::DESCRIPTION.to_string()),
        };
        let qf_prop_sort = QueryFilter {
            property: Some(prop.clone()),
            value: None,
            sort_by: Some(urls::DESCRIPTION.to_string()),
        };
        let qf_val_sort = QueryFilter {
            property: Some(prop),
            value: Some(Value::AtomicUrl(class.to_string())),
            sort_by: Some(urls::DESCRIPTION.to_string()),
        };

        // We should update with a sort_by attribute
        assert!(should_update(
            &qf_prop_val_sort,
            &index_atom,
            &resource_correct_class,
            false,
            store
        )
        .unwrap());
        assert!(should_update(
            &qf_prop_sort,
            &index_atom,
            &resource_correct_class,
            false,
            store
        )
        .unwrap());
        assert!(should_update(
            &qf_val_sort,
            &index_atom,
            &resource_correct_class,
            false,
            store
        )
        .unwrap());
    }
}
