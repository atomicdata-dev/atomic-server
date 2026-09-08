//! The QueryIndex is used to speed up queries by persisting filtered, sorted collections.
//! It relies on lexicographic ordering of keys, which Sled utilizes using `scan_prefix` queries.

use crate::{
    atoms::IndexAtom, errors::AtomicResult, storelike::Query, utils::truncate_string, Atom, Db,
    Resource, Storelike, Subject, Value,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::trees::{self, Operation, Transaction, Tree};

/// Returned by functions that iterate over [IndexAtom]s
pub type IndexIterator = Box<dyn Iterator<Item = AtomicResult<IndexAtom>> + Send>;

// `PropVal` lives in `storelike` (always compiled, unlike the feature-gated
// `db` module) so `Query` can reference it. Re-exported here for the index code
// and existing `query_index::PropVal` consumers.
pub use crate::storelike::{FilterOperator, PropVal};

/// A subset of a full [Query].
/// Represents a sorted filter on the Store.
/// A Value in the `watched_collections`.
/// Used as keys in the query_index.
/// These are used to check whether collections have to be updated when values have changed.
///
/// The `filters` are combined with **AND** semantics: a resource is a member
/// only if it matches every constraint. A single-constraint filter behaves
/// exactly like the old `property`/`value` pair.
///
/// Every `QueryFilter` is scoped to a specific drive. Cross-drive indexed queries are not supported.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryFilter {
    /// ANDed `(property, value)` constraints.
    pub filters: Vec<PropVal>,
    /// The property by which the collection is sorted
    pub sort_by: Option<String>,
    /// Drive scope: only index/match resources whose subject starts with this URL prefix.
    /// All watched queries must be drive-scoped to avoid spurious cross-tenant index updates.
    pub drive: Subject,
}

impl QueryFilter {
    #[tracing::instrument(skip_all)]
    /// Adds the QueryFilter to the `watched_queries` of the store.
    /// This means that whenever the store is updated (when a [Commit](crate::Commit) is added), the QueryFilter is checked.
    ///
    /// Routes through `Db::register_watched_query` so the in-memory
    /// `watched_queries_by_drive` map stays in sync. Repeated `watch()`
    /// calls for the same filter are idempotent.
    pub fn watch(&self, store: &Db) -> AtomicResult<()> {
        let has_constraint = self
            .filters
            .iter()
            .any(|c| c.property.is_some() || c.value.is_some());
        if !has_constraint {
            return Err("Cannot watch a query without a property or value. These types of queries are not implemented. See https://github.com/atomicdata-dev/atomic-server/issues/548 ".into());
        };
        store.register_watched_query(self.clone())
    }

    /// Check if this [QueryFilter] is being indexed
    pub fn is_watched(&self, store: &Db) -> bool {
        let query_filter_bin = self.encode().expect("Failed to encode QueryFilter");

        store
            .kv
            .contains_key(Tree::WatchedQueries, &query_filter_bin)
            .unwrap_or(false)
    }
}

impl QueryFilter {
    /// Constructs a QueryFilter from a Query that has a drive set.
    /// Returns an error if the query has no drive — all indexed queries must be drive-scoped.
    /// Convenience constructor for a single-constraint filter — mirrors the
    /// old `property`/`value` shape.
    pub fn single(
        property: Option<String>,
        value: Option<Value>,
        sort_by: Option<String>,
        drive: Subject,
    ) -> Self {
        QueryFilter {
            filters: vec![PropVal {
                property,
                value,
                ..Default::default()
            }],
            sort_by,
            drive,
        }
    }

    pub fn try_from_query(q: &Query) -> AtomicResult<Self> {
        let drive = q.drive.clone().ok_or(
            "Indexed queries require a drive scope. Set Query::drive to the drive Subject.",
        )?;
        let mut filters: Vec<PropVal> = Vec::new();
        // The primary `property`/`value` pair (back-compat) becomes the first
        // constraint.
        if q.property.is_some() || q.value.is_some() {
            filters.push(PropVal {
                property: q.property.clone(),
                value: q.value.clone(),
                operator: crate::storelike::FilterOperator::Equal,
            });
        }
        // Additional ANDed constraints.
        filters.extend(q.filters.iter().cloned());

        Ok(QueryFilter {
            filters,
            sort_by: q.sort_by.clone(),
            drive,
        })
    }
}

/// We can only store one bytearray as a key in Sled.
/// We separate the various items in it using this bit that's illegal in UTF-8.
/// Still used by the [Tree::PropValSub] / [Tree::ValPropSub] key layouts.
pub const SEPARATION_BIT: u8 = 0xff;

/// Length of the compact query id that prefixes every [Tree::QueryMembers]
/// key: a truncated blake3 hash of the filter's canonical encoding. 16 bytes
/// keeps accidental collisions out of reach (2^64 birthday bound) while
/// shrinking keys by the full serialized-filter prefix they used to carry.
pub const QUERY_ID_LEN: usize = 16;

/// The compact id a [QueryFilter] is indexed under in [Tree::QueryMembers]
/// and routed by in live `QUERY_UPDATE` events. Derived (not stored): hash of
/// the same canonical encoding used as the [Tree::WatchedQueries] key, which
/// remains the id → filter mapping.
pub fn query_id(query_filter: &QueryFilter) -> AtomicResult<[u8; QUERY_ID_LEN]> {
    let encoded = query_filter.encode()?;
    Ok(query_id_from_filter_bytes(&encoded))
}

/// [query_id] for callers that already hold the filter's canonical encoding.
pub fn query_id_from_filter_bytes(encoded_filter: &[u8]) -> [u8; QUERY_ID_LEN] {
    let hash = blake3::hash(encoded_filter);
    let mut id = [0u8; QUERY_ID_LEN];
    id.copy_from_slice(&hash.as_bytes()[..QUERY_ID_LEN]);
    id
}

// ── Typed, order-preserving sort keys ───────────────────────────────────────
//
// The sort segment of a QueryMembers key is a tag byte followed by a
// memcomparable payload, so plain byte comparison yields the right order
// across types: no-value < booleans < numbers < strings. Numbers (integers,
// floats, timestamps) share one f64 keyspace via the standard sign-flip
// encoding, which fixes the "2" > "10" lexicographic bug (#287). Strings are
// case-folded and truncated like before; ISO dates order correctly as
// strings. The payload never contains a bare 0x00 outside the fixed-length
// numeric encodings (strings escape it), so the 0x00 0x00 terminator that
// precedes the subject is unambiguous given the tag.

const TAG_NONE: u8 = 0x05;
const TAG_BOOL: u8 = 0x10;
const TAG_NUMBER: u8 = 0x20;
const TAG_STRING: u8 = 0x30;

/// Terminator between the sort segment and the subject bytes.
const SORT_TERMINATOR: [u8; 2] = [0x00, 0x00];

/// Maximum string length for values in the query_index. Should be long enough
/// to contain pretty long URLs, but not very long documents.
pub const MAX_LEN: usize = 120;

/// Encode a value into its order-preserving typed sort key.
/// `None` (resource lacks the sort property) sorts before everything.
pub fn encode_sort_value(value: Option<&Value>) -> Vec<u8> {
    match value {
        None => vec![TAG_NONE],
        Some(Value::Boolean(b)) => vec![TAG_BOOL, u8::from(*b)],
        Some(Value::Integer(i)) | Some(Value::Timestamp(i)) => encode_number(*i as f64),
        Some(Value::Float(f)) => encode_number(*f),
        Some(other) => encode_sort_string(&other.to_sortable_string()),
    }
}

fn encode_number(f: f64) -> Vec<u8> {
    let bits = f.to_bits();
    // Standard order-preserving f64 mapping: flip all bits for negatives,
    // flip only the sign bit for positives.
    let ordered = if bits >> 63 == 1 {
        !bits
    } else {
        bits ^ (1 << 63)
    };
    let mut out = Vec::with_capacity(9);
    out.push(TAG_NUMBER);
    out.extend_from_slice(&ordered.to_be_bytes());
    out
}

fn encode_sort_string(s: &str) -> Vec<u8> {
    let shorter = truncate_string(s, MAX_LEN);
    let lowercase = shorter.to_lowercase();
    let bytes = lowercase.as_bytes();
    let mut out = Vec::with_capacity(1 + bytes.len());
    out.push(TAG_STRING);
    for b in bytes {
        if *b == 0x00 {
            // Escape embedded NUL as 0x00 0xFF so it can't read as the
            // 0x00 0x00 terminator, while preserving order.
            out.push(0x00);
            out.push(0xFF);
        } else {
            out.push(*b);
        }
    }
    out
}

/// The encoded sort key a resource contributes to an index sorted by `prop`.
/// `sortOrder` falls back to `createdAt`: the property is defined as a
/// fractional sibling-order key that defaults to creation time, so explicitly
/// positioned resources interleave with untouched ones on one numeric axis —
/// no migration or backfill needed when a listing switches to sortOrder.
pub fn sort_key_for(resource: &Resource, prop: &str) -> Vec<u8> {
    let value = resource.get(prop).ok().cloned().or_else(|| {
        if prop == crate::urls::SORT_ORDER {
            resource.get(crate::urls::CREATED_AT).ok().cloned()
        } else {
            None
        }
    });
    encode_sort_value(value.as_ref())
}

#[tracing::instrument(skip_all)]
/// Performs a query on the `query_index` Tree, which is a lexicographic sorted list of all hits for QueryFilters.
pub async fn query_sorted_indexed(
    store: &Db,
    q: &Query,
    q_filter: &QueryFilter,
) -> AtomicResult<(Vec<Subject>, Vec<Resource>, usize)> {
    let id = query_id(q_filter)?;

    // Range bounds. A bare id prefix sorts before every member key with that
    // id; id || 0xFF sorts after every one (no sort tag reaches 0xFF and
    // subjects are UTF-8, which never contains 0xFF).
    let start_key: Vec<u8> = match &q.start_val {
        Some(val) => [id.as_slice(), &encode_sort_value(Some(val))].concat(),
        None => id.to_vec(),
    };
    let end_key: Vec<u8> = match &q.end_val {
        // Inclusive: the trailing 0xFF sorts after every subject entry that
        // shares this exact sort value.
        Some(val) => [id.as_slice(), &encode_sort_value(Some(val)), &[0xFF]].concat(),
        None => [id.as_slice(), &[0xFF]].concat(),
    };

    let iter = store
        .kv
        .range(Tree::QueryMembers, start_key, end_key, q.sort_desc);

    let mut subjects: Vec<Subject> = vec![];
    let mut resources: Vec<Resource> = vec![];
    let mut count = 0;

    let base_domain = store.get_base_domain();
    let rights_cache = std::sync::Mutex::new(crate::hierarchy::RightsCache::default());

    let limit = q.limit.unwrap_or(usize::MAX);

    for (i, kv) in iter.enumerate() {
        let kv = kv?;
        // The user's maximum amount of results has not yet been reached
        // and
        // The users minimum starting distance (offset) has been reached
        let in_selection = subjects.len() < limit && i >= q.offset;
        // Tracks whether this iter step should bump the visible count.
        // Defaults to true so entries past the page limit still count
        // (preserving the cheap-pagination behavior). Flipped to false
        // for in-page entries that don't survive include_external /
        // auth filtering, so count stays consistent with subjects.len()
        // for the page the client just received — eliminates the
        // `totalMembers: N, members: []` drift (issue #286).
        let mut should_count = true;
        if in_selection {
            let (k, _v) = &kv;
            let (_id, _sort, subject_str) = parse_members_key(k)?;

            let subject = Subject::from_raw(subject_str, base_domain.as_deref());

            if !q.include_external && !subject.is_local() {
                should_count = false;
            } else if q.for_agent != crate::agents::ForAgent::Sudo || q.include_nested {
                match store.resolve_query_member(&subject, q, &rights_cache).await {
                    Some(body) => {
                        subjects.push(subject);
                        if let Some(resource) = body {
                            resources.push(resource);
                        }
                    }
                    None => {
                        // Index hit that doesn't resolve for this agent
                        // (auth-filtered or destroyed-with-stale-index).
                        should_count = false;
                    }
                }
            } else {
                subjects.push(subject);
            }
        }

        // We iterate over every single resource, even if we don't perform any computation on the items.
        // This helps with pagination, but it comes at a serious performance cost. We might need to change how this works later on.
        // Also, this count does not take into account the `include_external` filter.
        if should_count {
            count += 1;
        }
        // https://github.com/atomicdata-dev/atomic-server/issues/290
    }

    Ok((subjects, resources, count))
}

/// Compares two values for ordering operators. Numeric when both parse as
/// numbers (covers Integer/Float/Timestamp and numeric strings); otherwise a
/// lexical comparison of their string forms (ISO dates sort correctly this way).
fn compare_values(actual: &Value, query: &Value) -> std::cmp::Ordering {
    let a = actual.to_string();
    let b = query.to_string();

    match (a.parse::<f64>(), b.parse::<f64>()) {
        (Ok(x), Ok(y)) => x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal),
        _ => a.cmp(&b),
    }
}

/// Whether a single resource value satisfies the constraint's value + operator.
fn value_matches(actual: &Value, query: &Value, operator: FilterOperator) -> bool {
    use std::cmp::Ordering;
    use FilterOperator::*;

    match operator {
        // Scalar equality or array membership — the historical behaviour.
        Equal => actual.contains_value(query),
        StartsWith => actual.to_string().starts_with(&query.to_string()),
        Contains => actual.to_string().contains(&query.to_string()),
        GreaterThan => compare_values(actual, query) == Ordering::Greater,
        GreaterThanOrEqual => {
            matches!(
                compare_values(actual, query),
                Ordering::Greater | Ordering::Equal
            )
        }
        LessThan => compare_values(actual, query) == Ordering::Less,
        LessThanOrEqual => {
            matches!(
                compare_values(actual, query),
                Ordering::Less | Ordering::Equal
            )
        }
    }
}

/// Whether a single `(property, value)` constraint matches a resource.
fn constraint_matches(resource: &Resource, c: &PropVal) -> bool {
    match (&c.property, &c.value) {
        (Some(property), Some(value)) => {
            matches!(resource.get(property), Ok(v) if value_matches(v, value, c.operator))
        }
        // Property only: the resource must have that property.
        (Some(property), None) => resource.get(property).is_ok(),
        // Value only: any property of the resource satisfies the constraint.
        (None, Some(value)) => resource
            .get_propvals()
            .iter()
            .any(|(_p, v)| value_matches(v, value, c.operator)),
        // No constraint at all is vacuously true (filtered out by `watch`).
        (None, None) => true,
    }
}

/// Whether a resource matches **all** of a QueryFilter's constraints (AND).
pub fn resource_matches_filter(resource: &Resource, q_filter: &QueryFilter) -> bool {
    q_filter
        .filters
        .iter()
        .all(|c| constraint_matches(resource, c))
}

/// Whether this atom is part of any of the filter's constraints (so a change
/// to it can flip membership and must trigger an index update).
fn atom_touches_constraint(q_filter: &QueryFilter, index_atom: &IndexAtom) -> bool {
    q_filter
        .filters
        .iter()
        .any(|c| match (&c.property, &c.value) {
            (Some(property), _) => property == &index_atom.property,
            (None, Some(value)) => value.to_string() == index_atom.ref_value,
            (None, None) => false,
        })
}

/// The property whose value is written into the index key for this filter.
/// `sort_by` wins (so members sort by it); otherwise the first constraint
/// property gives a stable bucket; failing that (all value-only) the atom's
/// own property is used.
pub(crate) fn index_key_property<'a>(
    q_filter: &'a QueryFilter,
    index_atom: &'a IndexAtom,
) -> &'a String {
    if let Some(sort_by) = &q_filter.sort_by {
        return sort_by;
    }
    for c in &q_filter.filters {
        if let Some(property) = &c.property {
            return property;
        }
    }
    &index_atom.property
}

/// Checks if a new IndexAtom should be updated for a specific [QueryFilter]
/// Returns which property should be updated, if any.
//
// Generalised for multi-constraint (AND) filters. The resource must match
// every constraint, and the changed atom must be relevant (it's the `sort_by`
// property or part of one of the constraints). The returned property
// determines which value lands in the index key (see `index_key_property`).
// See https://github.com/atomicdata-dev/atomic-server/issues/395 and #548.
pub fn should_update_property<'a>(
    q_filter: &'a QueryFilter,
    index_atom: &'a IndexAtom,
    resource: &Resource,
) -> Option<&'a String> {
    // The resource must be a member of the filter (all constraints match).
    if !resource_matches_filter(resource, q_filter) {
        return None;
    }

    // Is this specific atom relevant to the index? Either it's the sort key, or
    // it participates in one of the constraints (so changing it can flip
    // membership). If neither, the index key for this resource is unaffected.
    let touches_sort = q_filter
        .sort_by
        .as_ref()
        .is_some_and(|s| s == &index_atom.property);

    if !touches_sort && !atom_touches_constraint(q_filter, index_atom) {
        return None;
    }

    Some(index_key_property(q_filter, index_atom))
}

/// This is called when an atom is added or deleted.
/// Check whether the [Atom] will be hit by a [Query] matching the [QueryFilter].
/// Updates the index accordingly.
/// We need both the `index_atom` and the full `atom`.
///
/// Reads from the in-memory `watched_queries_by_drive` map populated by
/// `Db::populate_watched_queries_cache` at open and kept in sync by
/// `Db::register_watched_query`. The KV `Tree::WatchedQueries` is the
/// persistence layer; this hot path doesn't touch msgpack at all.
///
/// Filters are routed by `(drive, property)`: only filters that reference the
/// changed atom's property (in a constraint or as `sort_by`), plus the
/// drive's value-only filters, are evaluated — not every filter in the drive.
/// DID-subject atoms can't be prefix-matched to a single drive, so they
/// consult the property buckets of every drive.
#[tracing::instrument(level = "info", skip_all)]
pub fn check_if_atom_matches_watched_query_filters(
    store: &Db,
    index_atom: &IndexAtom,
    _atom: &Atom,
    delete: bool,
    resource: &Resource,
    transaction: &mut Transaction,
) -> AtomicResult<()> {
    let subject_str = index_atom.subject.as_str();

    let filters: Vec<Arc<QueryFilter>> = if subject_str.starts_with("did:") {
        store.all_watched_queries_for_property(&index_atom.property)
    } else {
        let drive_prefix = drive_prefix_from_subject(&index_atom.subject);
        store.watched_queries_for_atom(drive_prefix.as_str(), &index_atom.property)
    };

    tracing::trace!(
        "check_if_atom_matches_watched_query_filters: subject={}, atom_prop={}, filters_count={}",
        subject_str,
        index_atom.property,
        filters.len()
    );

    for q_filter in &filters {
        if let Some(prop) = should_update_property(q_filter, index_atom, resource) {
            let sort_key = sort_key_for(resource, prop);
            update_indexed_member(
                q_filter,
                index_atom.subject.as_str(),
                &sort_key,
                delete,
                transaction,
            )?;
        }
    }
    Ok(())
}

/// Adds or removes a single item (IndexAtom) to the [Tree::QueryMembers] cache.
/// `sort_key` is a typed key from [encode_sort_value] / [sort_key_for].
#[tracing::instrument(skip_all)]
pub fn update_indexed_member(
    collection: &QueryFilter,
    subject: &str,
    sort_key: &[u8],
    delete: bool,
    transaction: &mut Transaction,
) -> AtomicResult<()> {
    tracing::debug!(
        "update_indexed_member: subject={}, delete={}, filter={:?}",
        subject,
        delete,
        collection
    );
    let key = create_query_index_key(collection, Some(sort_key), Some(subject))?;
    if delete {
        transaction.push(Operation {
            tree: Tree::QueryMembers,
            method: trees::Method::Delete,
            key,
            val: None,
        })
    } else {
        transaction.push(Operation {
            tree: Tree::QueryMembers,
            method: trees::Method::Insert,
            key,
            val: Some(b"".into()),
        });
    }
    Ok(())
}

/// Creates a [Tree::QueryMembers] key:
/// `query_id(16B) || sort_key || 0x00 0x00 || subject`.
/// Byte order equals (filter, sort value, subject) order; see the typed
/// sort-key section above for why comparison is correct across types and
/// string prefixes.
#[tracing::instrument(skip_all)]
pub fn create_query_index_key(
    query_filter: &QueryFilter,
    sort_key: Option<&[u8]>,
    subject: Option<&str>,
) -> AtomicResult<Vec<u8>> {
    let id = query_id(query_filter)?;
    let mut key: Vec<u8> = Vec::with_capacity(
        QUERY_ID_LEN + sort_key.map_or(1, <[u8]>::len) + 2 + subject.map_or(0, str::len),
    );
    key.extend_from_slice(&id);
    key.extend_from_slice(sort_key.unwrap_or(&[TAG_NONE]));
    if let Some(sub) = subject {
        key.extend_from_slice(&SORT_TERMINATOR);
        key.extend_from_slice(sub.as_bytes());
    }
    Ok(key)
}

/// Parses a [Tree::QueryMembers] key into (query_id, sort_key, subject).
/// The sort segment's length is tag-determined (fixed for none/bool/number,
/// terminator-scanned for strings — escapes make the scan unambiguous).
#[tracing::instrument(skip_all)]
pub fn parse_members_key(bytes: &[u8]) -> AtomicResult<(&[u8], &[u8], &str)> {
    if bytes.len() < QUERY_ID_LEN + 1 {
        return Err("QueryMembers key too short".into());
    }
    let (id, rest) = bytes.split_at(QUERY_ID_LEN);
    let sort_len = match rest[0] {
        TAG_NONE => 1,
        TAG_BOOL => 2,
        TAG_NUMBER => 9,
        TAG_STRING => {
            // Scan for the unescaped 0x00 0x00 terminator. An escaped NUL is
            // 0x00 0xFF, so a 0x00 followed by 0x00 is always the terminator.
            let mut i = 1;
            loop {
                if i + 1 >= rest.len() {
                    return Err("QueryMembers key: unterminated string sort segment".into());
                }
                if rest[i] == 0x00 {
                    if rest[i + 1] == 0x00 {
                        break;
                    }
                    // Escaped byte — skip the pair.
                    i += 2;
                } else {
                    i += 1;
                }
            }
            i
        }
        other => return Err(format!("QueryMembers key: unknown sort tag {other:#x}").into()),
    };
    if rest.len() < sort_len + 2 || rest[sort_len] != 0x00 || rest[sort_len + 1] != 0x00 {
        return Err("QueryMembers key: missing sort terminator".into());
    }
    let sort = &rest[..sort_len];
    let subject = std::str::from_utf8(&rest[sort_len + 2..])
        .map_err(|e| format!("Can't parse subject in members_key: {}", e))?;
    Ok((id, sort, subject))
}

/// Extracts (query_id, subject) from a raw QueryMembers operation key, for
/// the `QueryMembershipChanged` event fan-out.
pub(crate) fn parse_members_key_id_subject(bytes: &[u8]) -> Option<(Vec<u8>, String)> {
    let (id, _sort, subject) = parse_members_key(bytes).ok()?;
    Some((id.to_vec(), subject.to_string()))
}

pub fn requires_query_index(query: &Query) -> bool {
    query.sort_by.is_some()
        || query.start_val.is_some()
        || query.end_val.is_some()
        // Multi-property (AND) filters can only be answered by the combined
        // index — the basic prop/val sub-index path matches a single constraint.
        || !query.filters.is_empty()
}

/// Extracts the drive prefix from a resource subject URL.
///
/// - `internal:/path` → `"internal:/"`
/// - `internal:tenant:/path` → `"internal:tenant:/"`
/// - `https://example.com/path` → `"https://example.com"`
/// - `did:ad:...` → the subject itself (DID subjects have no prefix drive)
pub fn drive_prefix_from_subject(subject: &Subject) -> Subject {
    let s = subject.as_str();
    let prefix = if s.starts_with("internal:") {
        // Matches both "internal:/path" and "internal:sub:/path"
        s.find(":/").map(|pos| s[..pos + 2].to_string())
    } else if s.starts_with("http://") || s.starts_with("https://") {
        url::Url::parse(s).ok().map(|url| {
            let host = url.host_str().unwrap_or("");
            match url.port() {
                Some(port) => format!("{}://{}:{}", url.scheme(), host, port),
                None => format!("{}://{}", url.scheme(), host),
            }
        })
    } else {
        None
    };
    Subject::from(prefix.unwrap_or_else(|| s.to_string()))
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::{urls, values::SubResource};

    /// Regression: real-world folder-table filters (where value is a DID
    /// Subject and property+sort_by are atomicdata.dev URLs) must round-trip
    /// through encode/from_bytes, and their member keys must parse back to
    /// the right id + subject.
    #[test]
    fn encode_decode_folder_table_filter() {
        use crate::Value;
        let filter = QueryFilter::single(
            Some("https://atomicdata.dev/properties/parent".to_string()),
            Some(Value::AtomicUrl(Subject::from(
                "did:ad:C1PsEdNI7K1D4N2dMVaaHwxwevsl/6pL8rSdejvD+ori3rZb6eafyTgeEVKCHPG0Po3SBQyT7Ea/7pB/Fl8PCg==",
            ))),
            Some("https://atomicdata.dev/properties/createdAt".to_string()),
            Subject::from("http://localhost:9883"),
        );

        let bytes = filter.encode().expect("encode");
        let decoded = QueryFilter::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded.filters[0].property, filter.filters[0].property);
        assert_eq!(decoded.sort_by, filter.sort_by);
        assert_eq!(decoded.drive.as_str(), filter.drive.as_str());

        // Round-trip through create_query_index_key + parse_members_key
        // — this is the path queries actually take.
        let sort_key = encode_sort_value(Some(&Value::String("2026-04-21".into())));
        let key = create_query_index_key(
            &filter,
            Some(&sort_key),
            Some("https://localhost/members/foo"),
        )
        .expect("create_query_index_key");
        let (id, sort, sub) = parse_members_key(&key).expect("parse_members_key");
        assert_eq!(id, query_id(&filter).unwrap());
        assert_eq!(sort, sort_key.as_slice());
        assert_eq!(sub, "https://localhost/members/foo");
    }

    #[tokio::test]
    async fn create_and_parse_key() {
        round_trip(Value::String("\n".into()));
        round_trip(Value::String("short".into()));
        round_trip(Value::String("with \0 embedded NUL".into()));
        round_trip(Value::Float(1.142));
        round_trip(Value::Float(-1.142));
        round_trip(Value::Integer(-42));
        round_trip(Value::Boolean(true));
        round_trip(Value::String("UPPERCASE".into()));
        round_trip(Value::String("29NA(E*Tn3028nt87n_#T&*NF_AE*&#N@_T*&!#B_&*TN&*AEBT&*#B&TB@#!#@BB29NA(E*Tn3028nt87n_#T&*NF_AE*&#N@_T*&!#B_&*TN&*AEBT&*#B&TB@#!#@BB29NA(E*Tn3028nt87n_#T&*NF_AE*&#N@_T*&!#B_&*TN&*AEBT&*#B&TB@#!#@BB29NA(E*Tn3028nt87n_#T&*NF_AE*&#N@_T*&!#B_&*TN&*AEBT&*#B&TB@#!#@BB".into()));

        /// Whatever the sort value, the key must parse back to the exact
        /// same id, sort segment, and subject.
        fn round_trip(val: Value) {
            let collection = QueryFilter::single(
                Some("http://example.org/prop".to_string()),
                Some(Value::AtomicUrl("http://example.org/value".into())),
                None,
                Subject::from("https://example.com"),
            );
            let subject = "https://example.com/subject";
            let sort_key = encode_sort_value(Some(&val));
            let key = create_query_index_key(&collection, Some(&sort_key), Some(subject)).unwrap();
            let (id, sort, sub_out) = parse_members_key(&key).unwrap();
            assert_eq!(id, query_id(&collection).unwrap());
            assert_eq!(sort, sort_key.as_slice());
            assert_eq!(sub_out, subject);
        }
    }

    /// Byte ordering of full member keys must equal the intended value
    /// ordering: no-value < booleans < numbers (numerically! #287) < strings
    /// (case-insensitive, correct for prefixes).
    #[test]
    fn typed_sort_key_ordering() {
        let q = QueryFilter::single(
            Some("http://example.org/prop".to_string()),
            Some(Value::AtomicUrl("http://example.org/value".into())),
            None,
            Subject::from("https://example.com"),
        );
        let key = |val: Option<&Value>| {
            create_query_index_key(
                &q,
                Some(&encode_sort_value(val)),
                Some("https://example.com/subject"),
            )
            .unwrap()
        };

        let no_value = key(None);
        let bool_false = key(Some(&Value::Boolean(false)));
        let bool_true = key(Some(&Value::Boolean(true)));
        let num_neg = key(Some(&Value::Float(-1.5)));
        let num_1 = key(Some(&Value::Integer(1)));
        let num_2 = key(Some(&Value::Float(2.0)));
        let num_10 = key(Some(&Value::Integer(10)));
        let num_1000 = key(Some(&Value::Float(1000.0)));
        let str_1 = key(Some(&Value::String("1".into())));
        let a_downcase = key(Some(&Value::String("a".into())));
        let ab = key(Some(&Value::String("ab".into())));
        let b_upcase = key(Some(&Value::String("B".into())));
        let mid3 = key(Some(&Value::String("hi there".into())));

        let expected = vec![
            &no_value,
            &bool_false,
            &bool_true,
            &num_neg,
            &num_1,
            &num_2,
            &num_10,
            &num_1000,
            &str_1,
            &a_downcase,
            &ab,
            &b_upcase,
            &mid3,
        ];
        let mut sorted = expected.clone();
        sorted.reverse();
        sorted.sort();
        assert_eq!(sorted, expected);

        // Integers and floats share one keyspace.
        assert_eq!(
            encode_sort_value(Some(&Value::Integer(2))),
            encode_sort_value(Some(&Value::Float(2.0)))
        );
    }

    /// Range-bound construction in `query_sorted_indexed`: a bare id sorts
    /// before every member key, id || 0xFF after every one, and a
    /// value-bound end key includes all subjects sharing that value.
    #[test]
    fn range_bounds_bracket_member_keys() {
        let q = QueryFilter::single(
            Some("http://example.org/prop".to_string()),
            None,
            None,
            Subject::from("https://example.com"),
        );
        let id = query_id(&q).unwrap();
        let entry = |val: &Value, subject: &str| {
            create_query_index_key(&q, Some(&encode_sort_value(Some(val))), Some(subject)).unwrap()
        };

        let low = entry(&Value::Integer(1), "https://example.com/a");
        let high = entry(&Value::String("zzz".into()), "https://example.com/z");

        let start: Vec<u8> = id.to_vec();
        let end: Vec<u8> = [id.as_slice(), &[0xFF]].concat();
        assert!(start < low && low < high && high < end);

        // Inclusive value-bound end: covers every subject with that value.
        let val = Value::String("middle".into());
        let bound: Vec<u8> = [id.as_slice(), &encode_sort_value(Some(&val)), &[0xFF]].concat();
        let member_a = entry(&val, "https://example.com/a");
        let member_z = entry(&val, "https://example.com/zzzzzz");
        assert!(member_a < bound && member_z < bound);
        // A string end-bound also covers its prefix extensions ("middle0"
        // ends before end_val "middle" + 0xFF) — parity with the previous
        // key layout, and what date bounds rely on ("2026-07-24T10:00"
        // falls inside an end bound of "2026-07-24").
        let extension = entry(&Value::String("middle0".into()), "https://example.com/a");
        assert!(extension < bound);
        // ...but a genuinely larger value is excluded.
        let next = entry(&Value::String("middlf".into()), "https://example.com/a");
        assert!(bound < next);
    }

    #[tokio::test]
    async fn should_update_or_not() {
        let store = &Db::init_temp("should_update_or_not").await.unwrap();

        let prop = urls::IS_A.to_string();
        let class = urls::AGENT;

        let qf_prop_val = QueryFilter::single(
            Some(prop.clone()),
            Some(Value::AtomicUrl(class.to_string().into())),
            None,
            Subject::from("https://example.com"),
        );

        let qf_prop = QueryFilter::single(
            Some(prop.clone()),
            None,
            None,
            Subject::from("https://example.com"),
        );

        let qf_val = QueryFilter::single(
            None,
            Some(Value::AtomicUrl(class.to_string().into())),
            None,
            Subject::from("https://example.com"),
        );

        let mut resource_correct_class = Resource::new_instance(class, store).await.unwrap();

        resource_correct_class
            .set(
                urls::IS_A.into(),
                Value::ResourceArray(vec![
                    SubResource::Subject(class.to_string().into()),
                    SubResource::Subject(urls::PARAGRAPH.to_string().into()),
                ]),
                store,
            )
            .await
            .unwrap();

        resource_correct_class
            .set(
                urls::PUBLIC_KEY.into(),
                Value::String("This is not a public key but it should be fine".into()),
                store,
            )
            .await
            .unwrap();
        resource_correct_class
            .set(
                urls::DESCRIPTION.into(),
                Value::Markdown("random description".into()),
                store,
            )
            .await
            .unwrap();

        let subject = Subject::from("https://example.com/someAgent");

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
        let resource_wrong_class = Resource::new_instance(urls::PARAGRAPH, store)
            .await
            .unwrap();
        assert!(should_update_property(&qf_prop, &index_atom, &resource_wrong_class).is_some());
        assert!(should_update_property(&qf_val, &index_atom, &resource_wrong_class).is_none());
        assert!(should_update_property(&qf_prop_val, &index_atom, &resource_wrong_class).is_none());

        let qf_prop_val_sort = QueryFilter::single(
            Some(prop.clone()),
            Some(Value::AtomicUrl(class.to_string().into())),
            Some(urls::DESCRIPTION.to_string()),
            Subject::from("https://example.com"),
        );
        let qf_prop_sort = QueryFilter::single(
            Some(prop.clone()),
            None,
            Some(urls::DESCRIPTION.to_string()),
            Subject::from("https://example.com"),
        );
        let qf_val_sort = QueryFilter::single(
            Some(prop),
            Some(Value::AtomicUrl(class.to_string().into())),
            Some(urls::DESCRIPTION.to_string()),
            Subject::from("https://example.com"),
        );

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

    /// Multi-property AND: a resource is a member only when it matches every
    /// constraint, and a change to any constraint property triggers an update.
    #[tokio::test]
    async fn multi_property_and_filter() {
        let store = &Db::init_temp("multi_property_and_filter").await.unwrap();
        let class = urls::AGENT;
        let drive = Subject::from("https://example.com");

        let mut resource = Resource::new_instance(class, store).await.unwrap();
        resource
            .set(
                urls::DESCRIPTION.into(),
                Value::Markdown("hello".into()),
                store,
            )
            .await
            .unwrap();

        // isA = Agent AND description = "hello"
        let matching = QueryFilter {
            filters: vec![
                PropVal {
                    property: Some(urls::IS_A.to_string()),
                    value: Some(Value::AtomicUrl(class.to_string().into())),
                    ..Default::default()
                },
                PropVal {
                    property: Some(urls::DESCRIPTION.to_string()),
                    value: Some(Value::String("hello".into())),
                    ..Default::default()
                },
            ],
            sort_by: None,
            drive: drive.clone(),
        };

        // isA = Agent AND description = "different"
        let non_matching = QueryFilter {
            filters: vec![
                PropVal {
                    property: Some(urls::IS_A.to_string()),
                    value: Some(Value::AtomicUrl(class.to_string().into())),
                    ..Default::default()
                },
                PropVal {
                    property: Some(urls::DESCRIPTION.to_string()),
                    value: Some(Value::String("different".into())),
                    ..Default::default()
                },
            ],
            sort_by: None,
            drive,
        };

        assert!(resource_matches_filter(&resource, &matching));
        assert!(!resource_matches_filter(&resource, &non_matching));

        // A change to the `isA` atom updates the matching filter's index...
        let is_a_atom = IndexAtom {
            subject: Subject::from("https://example.com/someAgent"),
            property: urls::IS_A.to_string(),
            ref_value: class.to_string(),
            sort_value: class.to_string(),
        };
        assert!(should_update_property(&matching, &is_a_atom, &resource).is_some());
        // ...but not the non-matching one (description constraint fails).
        assert!(should_update_property(&non_matching, &is_a_atom, &resource).is_none());

        // A change to the `description` atom (the second constraint prop) also
        // triggers an update for the matching filter.
        let desc_atom = IndexAtom {
            subject: Subject::from("https://example.com/someAgent"),
            property: urls::DESCRIPTION.to_string(),
            ref_value: "hello".to_string(),
            sort_value: "hello".to_string(),
        };
        assert!(should_update_property(&matching, &desc_atom, &resource).is_some());
    }

    #[tokio::test]
    async fn operator_filters() {
        let store = &Db::init_temp("operator_filters").await.unwrap();
        let drive = Subject::from("https://example.com");

        let mut resource = Resource::new_instance(urls::AGENT, store).await.unwrap();
        resource
            .set(
                urls::DESCRIPTION.into(),
                Value::Markdown("hello world".into()),
                store,
            )
            .await
            .unwrap();
        // A numeric value to exercise the comparison operators.
        resource
            .set_unsafe(urls::COLLECTION_PAGE_SIZE.into(), Value::Integer(42))
            .unwrap();

        let f = |property: &str, value: Value, operator: FilterOperator| QueryFilter {
            filters: vec![PropVal {
                property: Some(property.to_string()),
                value: Some(value),
                operator,
            }],
            sort_by: None,
            drive: drive.clone(),
        };

        use FilterOperator::*;

        // starts_with / contains on the markdown description.
        let sw = |v: &str| f(urls::DESCRIPTION, Value::String(v.into()), StartsWith);
        assert!(resource_matches_filter(&resource, &sw("hello")));
        assert!(!resource_matches_filter(&resource, &sw("world")));

        let ct = |v: &str| f(urls::DESCRIPTION, Value::String(v.into()), Contains);
        assert!(resource_matches_filter(&resource, &ct("lo wo")));
        assert!(!resource_matches_filter(&resource, &ct("xyz")));

        // Numeric comparisons against 42.
        let num = |v: i64, op: FilterOperator| f(urls::COLLECTION_PAGE_SIZE, Value::Integer(v), op);
        assert!(resource_matches_filter(&resource, &num(10, GreaterThan)));
        assert!(!resource_matches_filter(&resource, &num(50, GreaterThan)));
        assert!(resource_matches_filter(
            &resource,
            &num(42, GreaterThanOrEqual)
        ));
        assert!(resource_matches_filter(&resource, &num(100, LessThan)));
        assert!(!resource_matches_filter(&resource, &num(42, LessThan)));
        assert!(resource_matches_filter(
            &resource,
            &num(42, LessThanOrEqual)
        ));
    }
}
