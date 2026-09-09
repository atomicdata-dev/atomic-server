//! Parsing pagination state back out of a server response.

use indexmap::IndexMap;
use serde_json::{Map, Value};

use super::types::{PaginationResponseState, PaginationSchemeObject, ResponseRole, SchemeType};

/// Reads a dot-separated path out of a JSON object, e.g. `pagination.total_count`.
pub fn read_nested_field<'v>(body: &'v Value, path: &str) -> Option<&'v Value> {
    let mut node = body;
    for segment in path.split('.') {
        node = node.as_object()?.get(segment)?;
    }
    Some(node)
}

/// Writes a value at a dot-separated path, creating intermediate objects
/// as needed.
pub fn set_nested_field(body: &mut Map<String, Value>, path: &str, value: Value) {
    let segments: Vec<&str> = path.split('.').collect();
    let Some((last, parents)) = segments.split_last() else {
        return;
    };

    let mut node = body;
    for segment in parents {
        let entry = node
            .entry((*segment).to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if !entry.is_object() {
            *entry = Value::Object(Map::new());
        }
        node = entry.as_object_mut().expect("just ensured object");
    }
    node.insert((*last).to_string(), value);
}

/// Parses an RFC 8288 `Link` header value and extracts the URL with
/// `rel="next"`.
///
/// Example: `<https://api.example.com/items?page=2>; rel="next", <...>; rel="prev"`
pub fn parse_link_header(header: &str) -> Option<String> {
    if header.is_empty() {
        return None;
    }
    for part in split_links(header) {
        let part = part.trim_start();
        let Some(rest) = part.strip_prefix('<') else {
            continue;
        };
        let Some(end) = rest.find('>') else {
            continue;
        };
        let (url, attrs) = rest.split_at(end);
        if rel_is_next(&attrs[1..]) {
            return Some(url.to_string());
        }
    }
    None
}

/// Splits on commas that begin a new `<url>` link-value, mirroring the
/// original's `/,\s*(?=<)/` lookahead.
fn split_links(header: &str) -> Vec<&str> {
    let bytes = header.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b',' {
            continue;
        }
        let after = header[index + 1..].trim_start();
        if after.starts_with('<') {
            parts.push(&header[start..index]);
            start = index + 1;
        }
    }
    parts.push(&header[start..]);
    parts
}

/// Finds `rel=next` (quoted or bare) among a link-value's attributes.
fn rel_is_next(attrs: &str) -> bool {
    let lowered = attrs.to_ascii_lowercase();
    let mut search = lowered.as_str();
    while let Some(index) = search.find("rel") {
        let before_is_boundary = index == 0
            || !search.as_bytes()[index - 1].is_ascii_alphanumeric()
                && search.as_bytes()[index - 1] != b'_';
        let after = search[index + 3..].trim_start();
        if before_is_boundary {
            if let Some(value) = after.strip_prefix('=') {
                let value = value.trim_start().trim_start_matches('"');
                let value = value
                    .split(|c: char| c == '"' || c == ';' || c == ',' || c.is_whitespace())
                    .next()
                    .unwrap_or("");
                if value == "next" {
                    return true;
                }
            }
        }
        search = &search[index + 3..];
    }
    false
}

fn to_string_or_none(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::Null => None,
        Value::String(s) if s.is_empty() => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

fn to_number_or_none(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        Value::Bool(b) => Some(f64::from(u8::from(*b))),
        _ => None,
    }
}

fn extract_by_role(
    scheme: &PaginationSchemeObject,
    body: &Value,
    headers: &IndexMap<String, String>,
) -> IndexMap<ResponseRole, Value> {
    let mut roles = IndexMap::new();

    let response = scheme.response.as_ref();

    for (path, field) in response
        .and_then(|r| r.body_fields.as_ref())
        .into_iter()
        .flatten()
    {
        let Some(role) = &field.role else { continue };
        if let Some(value) = read_nested_field(body, path) {
            roles.insert(role.clone(), value.clone());
        }
    }

    for (name, field) in response
        .and_then(|r| r.headers.as_ref())
        .into_iter()
        .flatten()
    {
        let Some(role) = &field.role else { continue };
        let raw = headers
            .get(name)
            .or_else(|| headers.get(&name.to_lowercase()))
            .or_else(|| headers.get(&name.to_uppercase()));
        let Some(raw) = raw else { continue };
        if role == "nextLink" {
            if let Some(parsed) = parse_link_header(raw) {
                roles.insert("nextLink".to_string(), Value::String(parsed));
            }
        } else {
            roles.insert(role.clone(), Value::String(raw.clone()));
        }
    }

    roles
}

/// A `nextLink`/`nextPageToken` value is a strong, type-agnostic signal
/// that another page exists — real APIs sometimes include one even on a
/// scheme whose `type` is `pageNumber` (e.g. Spotify's offset-based
/// endpoints all carry a `next` URL). Checking it first, ahead of the
/// type-specific counting rules, means traversal still terminates
/// correctly for those schemes even without a `currentPage`/`totalPages`
/// role declared.
///
/// `totalCount` (role: `all` per spec §4.5) is checked next against
/// `items_fetched_so_far`, which the *caller* tracks — some real schemes
/// (e.g. Giphy's) report `totalCount` and `pageSize` but no `currentPage`
/// at all, so there's nothing here to compute "current page * pageSize"
/// from; the client already knows exactly how many items it has pulled
/// across all pages so far, which is the more direct signal anyway.
fn derive_has_next_page(
    scheme_type: Option<SchemeType>,
    state: &PaginationResponseState,
    items_fetched_so_far: Option<u64>,
) -> bool {
    if state.next_link.is_some() || state.next_page_token.is_some() {
        return true;
    }
    if let (Some(total_count), Some(fetched)) = (state.total_count, items_fetched_so_far) {
        #[allow(clippy::cast_precision_loss)]
        return (fetched as f64) < total_count;
    }
    if scheme_type == Some(SchemeType::PageNumber) {
        if let (Some(current_page), Some(total_pages)) = (state.current_page, state.total_pages) {
            return current_page < total_pages;
        }
        if let (Some(current_page), Some(total_count), Some(page_size)) =
            (state.current_page, state.total_count, state.page_size)
        {
            return current_page * page_size < total_count;
        }
    }
    false
}

/// Parses a server response into pagination state, per the resolved scheme.
///
/// `items_fetched_so_far` — the cumulative item count across all pages
/// fetched so far, including this one — lets `has_next_page` be derived
/// from a plain `totalCount` field even when no `currentPage` role is
/// declared.
pub fn parse_pagination_state(
    scheme: &PaginationSchemeObject,
    body: &Value,
    headers: &IndexMap<String, String>,
    items_fetched_so_far: Option<u64>,
) -> PaginationResponseState {
    let roles = extract_by_role(scheme, body, headers);

    let mut state = PaginationResponseState {
        next_page_token: to_string_or_none(
            roles
                .get("nextPageToken")
                .or_else(|| roles.get("nextCursor")),
        ),
        next_link: to_string_or_none(roles.get("nextLink")),
        current_page: to_number_or_none(roles.get("currentPage")),
        total_count: to_number_or_none(roles.get("totalCount")),
        total_pages: to_number_or_none(roles.get("totalPages")),
        page_size: to_number_or_none(roles.get("pageSize")),
        has_next_page: false,
    };
    state.has_next_page = derive_has_next_page(scheme.typed(), &state, items_fetched_so_far);
    state
}
