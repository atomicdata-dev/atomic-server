//! The QueryIndex is used to speed up queries by persisting filtered, sorted collections.
//! It relies on lexicographic ordering of keys, which Sled utilizes using `scan_prefix` queries.

use crate::{
    atoms::IndexAtom,
    errors::AtomicResult,
    storelike::{Query, QueryResult},
    values::SortableValue,
    Atom, Db, Resource, Storelike, Value,
};
use serde::{Deserialize, Serialize};

/// Returned by functions that iterate over [IndexAtom]s
pub type IndexIterator = Box<dyn Iterator<Item = AtomicResult<IndexAtom>>>;

/// A subset of a full [Query].
/// Represents a sorted filter on the Store.
/// A Value in the `watched_collections`.
/// Used as keys in the query_index.
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

impl QueryFilter {
    #[tracing::instrument(skip(store))]
    /// Adds the QueryFilter to the `watched_queries` of the store.
    /// This means that whenever the store is updated (when a [Commit](crate::Commit) is added), the QueryFilter is checked.
    pub fn watch(&self, store: &Db) -> AtomicResult<()> {
        if self.property.is_none() && self.value.is_none() {
            return Err("Cannot watch a query without a property or value. These types of queries are not implemented. See https://github.com/atomicdata-dev/atomic-data-rust/issues/548 ".into());
        };
        store
            .watched_queries
            .insert(bincode::serialize(self)?, b"")?;
        Ok(())
    }

    /// Check if this [QueryFilter] is being indexed
    pub fn is_watched(&self, store: &Db) -> bool {
        store
            .watched_queries
            .contains_key(bincode::serialize(self).unwrap())
            .unwrap_or(false)
    }
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

/// Last character in lexicographic ordering
pub const FIRST_CHAR: &str = "\u{0000}";
pub const END_CHAR: &str = "\u{ffff}";
/// We can only store one bytearray as a key in Sled.
/// We separate the various items in it using this bit that's illegal in UTF-8.
pub const SEPARATION_BIT: u8 = 0xff;
/// If we want to sort by a value that is no longer there, we use this special value.
pub const NO_VALUE: &str = "";

#[tracing::instrument(skip(store))]
/// Performs a query on the `query_index` Tree, which is a lexicographic sorted list of all hits for QueryFilters.
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
    let start_key = create_query_index_key(&q.into(), Some(&start.to_sortable_string()), None)?;
    let end_key = create_query_index_key(&q.into(), Some(&end.to_sortable_string()), None)?;

    let iter: Box<dyn Iterator<Item = std::result::Result<(sled::IVec, sled::IVec), sled::Error>>> =
        if q.sort_desc {
            Box::new(store.query_index.range(start_key..end_key).rev())
        } else {
            Box::new(store.query_index.range(start_key..end_key))
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
                    Err(e) => match &e.error_type {
                        crate::AtomicErrorType::NotFoundError => {}
                        crate::AtomicErrorType::UnauthorizedError => {}
                        _other => {
                            return Err(format!(
                                "Error when getting resource in collection: {}",
                                &e
                            )
                            .into());
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
        // https://github.com/atomicdata-dev/atomic-data-rust/issues/290
        count = i + 1;
    }

    Ok(QueryResult {
        count,
        resources,
        subjects,
    })
}

/// Checks if the resource will match with a QueryFilter.
/// Does any value or property or sort value match?
/// Returns the matching property, if found.
/// E.g. if a Resource
fn find_matching_propval<'a>(
    resource: &'a Resource,
    q_filter: &'a QueryFilter,
) -> Option<&'a String> {
    if let Some(property) = &q_filter.property {
        if let Ok(matched_val) = resource.get(property) {
            if let Some(filter_val) = &q_filter.value {
                if matched_val.to_string() == filter_val.to_string() {
                    return Some(property);
                }
            } else {
                return Some(property);
            }
        }
    } else if let Some(filter_val) = &q_filter.value {
        for (prop, val) in resource.get_propvals() {
            if val.contains_value(filter_val) {
                return Some(prop);
            }
        }
        return None;
    }
    None
}

/// Checks if a new IndexAtom should be updated for a specific [QueryFilter]
/// Returns which property should be updated, if any.
// This is probably the most complex function in the whole repo.
// If things go wrong when making changes, add a test and fix stuff in the logic below.
pub fn should_update_property<'a>(
    q_filter: &'a QueryFilter,
    index_atom: &'a IndexAtom,
    resource: &Resource,
) -> Option<&'a String> {
    // First we'll check if the resource matches the QueryFilter.
    // We'll need the `matching_val` for updating the index when a value changes that influences other indexed members.
    // For example, if we have a Query for children of a particular folder, sorted by name,
    // and we move one of the children to a different folder, we'll need to make sure that the index is updated containing the name of the child.
    // This name is not part of the `index_atom` itself, as the name wasn't updated.
    // So here we not only make sure that the QueryFilter actually matches the resource,
    // But we also return which prop & val we matched on, so we can update the index with the correct value.
    // See https://github.com/atomicdata-dev/atomic-data-rust/issues/395
    let matching_prop = match find_matching_propval(resource, q_filter) {
        Some(a) => a,
        // if the resource doesn't match the filter, we don't need to update the index
        None => return None,
    };

    // Now we know that our new Resource is a member for this QueryFilter.
    // But we don't know whether this specific IndexAtom is relevant for the index of this QueryFilter.
    // There are three possibilities:
    // 1. The Atom is not relevant for the index, and we don't need to update the index.
    // 2. The Atom is directly relevant for the index, and we need to update the index using the value of the IndexAtom.
    // 3. The Atom is indirectly relevant for the index. This only happens if there is a `sort_by`.
    //    The Atom influences if the QueryFilter hits, and we need to construct a Key in the index with
    //    a value from another Property.
    match (&q_filter.property, &q_filter.value, &q_filter.sort_by) {
        // Whenever the atom matches with either the sorted or the filtered prop, we have to update
        (Some(_filterprop), Some(_filter_val), Some(sortprop)) => {
            if sortprop == &index_atom.property || matching_prop == &index_atom.property {
                // Update the Key, which contains the sorted prop & value.
                return Some(sortprop);
            }
            None
        }
        (Some(_filterprop), None, Some(sortprop)) => {
            if sortprop == &index_atom.property || matching_prop == &index_atom.property {
                return Some(sortprop);
            }
            None
        }
        (Some(filter_prop), Some(_filter_val), None) => {
            if filter_prop == &index_atom.property {
                // Update the Key, which contains the filtered value
                return Some(filter_prop);
            }
            None
        }
        (Some(filter_prop), None, None) => {
            if filter_prop == &index_atom.property {
                return Some(filter_prop);
            }
            None
        }
        (None, Some(filter_val), None) => {
            if filter_val.to_string() == index_atom.ref_value {
                return Some(&index_atom.property);
            }
            None
        }
        (None, Some(filter_val), Some(sort_by)) => {
            if filter_val.to_string() == index_atom.ref_value || &index_atom.property == sort_by {
                return Some(sort_by);
            }
            None
        }
        // TODO: Consider if we should allow the following indexes this.
        // See https://github.com/atomicdata-dev/atomic-data-rust/issues/548
        // When changing these, also update [QueryFilter::watch]
        (None, None, None) => None,
        (None, None, Some(_)) => None,
    }
}

/// This is called when an atom is added or deleted.
/// Check whether the [Atom] will be hit by a [Query] matching the [QueryFilter].
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

            if let Some(prop) = should_update_property(&q_filter, index_atom, resource) {
                let update_val = match resource.get(prop) {
                    Ok(val) => val.to_sortable_string(),
                    Err(_e) => NO_VALUE.to_string(),
                };
                update_indexed_member(store, &q_filter, &atom.subject, &update_val, delete)?;
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
    value: &SortableValue,
    delete: bool,
) -> AtomicResult<()> {
    let key = create_query_index_key(
        collection,
        // Maybe here we should serialize the value a bit different - as a sortable string, where Arrays are sorted by their length.
        Some(value),
        Some(subject),
    )?;
    if delete {
        store.query_index.remove(key)?;
    } else {
        store.query_index.insert(key, b"")?;
    }
    Ok(())
}

/// Maximum string length for values in the query_index. Should be long enough to contain pretty long URLs, but not very long documents.
// Consider moving this to [Value::to_sortable_string]
pub const MAX_LEN: usize = 120;

/// Creates a key for a collection + value combination.
/// These are designed to be lexicographically sortable.
#[tracing::instrument()]
pub fn create_query_index_key(
    query_filter: &QueryFilter,
    value: Option<&SortableValue>,
    subject: Option<&str>,
) -> AtomicResult<Vec<u8>> {
    let mut q_filter_bytes: Vec<u8> = bincode::serialize(query_filter)?;
    q_filter_bytes.push(SEPARATION_BIT);

    let mut value_bytes: Vec<u8> = if let Some(val) = value {
        let val_string = val;
        let shorter = if val_string.len() > MAX_LEN {
            &val_string[0..MAX_LEN]
        } else {
            val_string
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
            let key =
                create_query_index_key(&collection, Some(&val.to_sortable_string()), Some(subject))
                    .unwrap();
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
        let num_1 = create_query_index_key(&q, Some(&Value::Float(1.0).to_sortable_string()), None)
            .unwrap();
        let num_2 = create_query_index_key(&q, Some(&Value::Float(2.0).to_sortable_string()), None)
            .unwrap();
        // let num_10 = create_query_index_key(&q, Some(&Value::Float(10.0)), None).unwrap();
        let num_1000 =
            create_query_index_key(&q, Some(&Value::Float(1000.0).to_sortable_string()), None)
                .unwrap();
        let start_str = create_query_index_key(
            &q,
            Some(&Value::String("1".into()).to_sortable_string()),
            None,
        )
        .unwrap();
        let a_downcase = create_query_index_key(
            &q,
            Some(&Value::String("a".into()).to_sortable_string()),
            None,
        )
        .unwrap();
        let b_upcase = create_query_index_key(
            &q,
            Some(&Value::String("B".into()).to_sortable_string()),
            None,
        )
        .unwrap();
        let mid3 = create_query_index_key(
            &q,
            Some(&Value::String("hi there".into()).to_sortable_string()),
            None,
        )
        .unwrap();
        let end = create_query_index_key(
            &q,
            Some(&Value::String(END_CHAR.into()).to_sortable_string()),
            None,
        )
        .unwrap();

        assert!(start_none < num_1);
        assert!(num_1 < num_2);
        // TODO: Fix sorting numbers
        // https://github.com/atomicdata-dev/atomic-data-rust/issues/287
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
            ref_value: class.to_string(),
            sort_value: class.to_string(),
        };

        // We should be able to find the resource by propval, val, and / or prop.
        assert!(should_update_property(&qf_val, &index_atom, &resource_correct_class).is_some());
        assert!(
            should_update_property(&qf_prop_val, &index_atom, &resource_correct_class,).is_some()
        );
        assert!(should_update_property(&qf_prop, &index_atom, &resource_correct_class).is_some());

        // Test when a different value is passed
        let resource_wrong_class = Resource::new_instance(urls::PARAGRAPH, store).unwrap();
        assert!(should_update_property(&qf_prop, &index_atom, &resource_wrong_class).is_some());
        assert!(should_update_property(&qf_val, &index_atom, &resource_wrong_class).is_none());
        assert!(should_update_property(&qf_prop_val, &index_atom, &resource_wrong_class).is_none());

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
        assert!(
            should_update_property(&qf_prop_val_sort, &index_atom, &resource_correct_class,)
                .is_some()
        );
        assert!(
            should_update_property(&qf_prop_sort, &index_atom, &resource_correct_class,).is_some()
        );
        assert!(
            should_update_property(&qf_val_sort, &index_atom, &resource_correct_class,).is_some()
        );
    }
}
