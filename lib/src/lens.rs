//! Lenses: content-addressed mappings between two properties.
//!
//! Properties are immutable, so renaming a shortname or changing a datatype
//! makes a new Property and strands the data stored under the old one. A Lens
//! says how a value under one Property maps to a value under another. It is
//! applied when a resource's Loro document is materialized into its propvals;
//! the document itself (signed data) is never changed by a lens.
//!
//! See `docs/src/schema/lenses.md`. The TypeScript twin is
//! `browser/lib/src/lens.ts`; both read `lib/tests/fixtures/lenses.json`.

use crate::{
    datatype::{match_datatype, DataType},
    errors::AtomicResult,
    identifiers::{self, ATOMIC_LENS_PREFIX},
    resources::PropVals,
    urls,
    values::{SubResource, Value},
};
use serde_json::{json, Map, Number, Value as Json};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

/// Domain separation for lens IDs. Keeps them apart from property IDs and
/// blob hashes.
const LENS_CONTEXT: &str = "atomic lens identity v1";

/// Largest integer both Rust and JavaScript represent exactly.
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// What a lens does to a value. Each op has a forward direction (`from` to
/// `to`) and, except for a non-injective `map`, a backward direction.
#[derive(Clone, Debug, PartialEq)]
pub enum Transform {
    /// The same value under another name.
    Rename,
    /// Scalar to a one-item array. Backward: [`Transform::Head`] of a one-item array.
    Wrap,
    /// Array to its first item. Backward: [`Transform::Wrap`].
    Head,
    /// Value mapping (an enum rename). Values not listed pass through.
    Map(BTreeMap<String, String>),
    /// Parse or format between a string-like datatype and integer, float or boolean.
    Convert {
        /// Datatype of the forward result.
        to: String,
        /// Datatype of the backward result. `string` when absent.
        from: Option<String>,
    },
}

impl Transform {
    /// Parse and validate the `lensTransform` JSON. Unknown ops and unknown
    /// fields are rejected, so equal transforms hash equal.
    pub fn parse(json: &Json) -> AtomicResult<Transform> {
        let obj = json
            .as_object()
            .ok_or("A lens transform must be a JSON object")?;
        let op = obj
            .get("op")
            .and_then(Json::as_str)
            .ok_or("A lens transform needs a string `op`")?;
        let allowed: &[&str] = match op {
            "rename" | "wrap" | "head" => &["op"],
            "map" => &["op", "values"],
            "convert" => &["op", "to", "from"],
            other => return Err(format!("Unknown lens op: '{other}'").into()),
        };
        if let Some(extra) = obj.keys().find(|k| !allowed.contains(&k.as_str())) {
            return Err(format!("Unknown field '{extra}' in lens op '{op}'").into());
        }
        Ok(match op {
            "rename" => Transform::Rename,
            "wrap" => Transform::Wrap,
            "head" => Transform::Head,
            "map" => {
                let values = obj
                    .get("values")
                    .and_then(Json::as_object)
                    .ok_or("Lens op 'map' needs an object `values`")?;
                let mut map = BTreeMap::new();
                for (k, v) in values {
                    let v = v
                        .as_str()
                        .ok_or("Lens op 'map' values must map strings to strings")?;
                    map.insert(k.clone(), v.to_string());
                }
                Transform::Map(map)
            }
            _ => {
                let datatype = |key: &str| -> AtomicResult<Option<String>> {
                    match obj.get(key) {
                        None => Ok(None),
                        Some(v) => {
                            let s = v.as_str().ok_or_else(|| {
                                format!("Lens op 'convert' `{key}` must be a string")
                            })?;
                            if matches!(match_datatype(s), DataType::Unsupported(_)) {
                                return Err(format!("Unknown datatype: '{s}'").into());
                            }
                            Ok(Some(s.to_string()))
                        }
                    }
                };
                Transform::Convert {
                    to: datatype("to")?.ok_or("Lens op 'convert' needs a `to` datatype")?,
                    from: datatype("from")?,
                }
            }
        })
    }

    /// The canonical JSON form (what is hashed and stored).
    pub fn to_json(&self) -> Json {
        match self {
            Transform::Rename => json!({"op": "rename"}),
            Transform::Wrap => json!({"op": "wrap"}),
            Transform::Head => json!({"op": "head"}),
            Transform::Map(values) => json!({"op": "map", "values": values}),
            Transform::Convert { to, from } => {
                let mut obj = Map::new();
                obj.insert("op".into(), json!("convert"));
                obj.insert("to".into(), json!(to));
                if let Some(from) = from {
                    obj.insert("from".into(), json!(from));
                }
                Json::Object(obj)
            }
        }
    }

    /// Whether `backward` can ever yield a value. False for a `map` that sends
    /// two values to one.
    pub fn has_backward(&self) -> bool {
        match self {
            Transform::Map(values) => {
                let mut seen = std::collections::HashSet::new();
                values.values().all(|v| seen.insert(v))
            }
            _ => true,
        }
    }

    /// `from` value to `to` value. `None` means there is no derived value.
    pub fn forward(&self, value: &Json) -> Option<Json> {
        match self {
            Transform::Rename => Some(value.clone()),
            Transform::Wrap => wrap(value),
            Transform::Head => head(value),
            Transform::Map(values) => map_value(values, value),
            Transform::Convert { to, .. } => convert(value, to),
        }
    }

    /// `to` value back to a `from` value. `None` means there is no derived value.
    pub fn backward(&self, value: &Json) -> Option<Json> {
        if !self.has_backward() {
            return None;
        }
        match self {
            Transform::Rename => Some(value.clone()),
            // Only an array of exactly one item maps back without loss.
            Transform::Wrap => match value.as_array() {
                Some(items) if items.len() == 1 => Some(items[0].clone()),
                _ => None,
            },
            Transform::Head => wrap(value),
            Transform::Map(values) => {
                let inverse: BTreeMap<String, String> =
                    values.iter().map(|(k, v)| (v.clone(), k.clone())).collect();
                map_value(&inverse, value)
            }
            Transform::Convert { from, .. } => {
                convert(value, from.as_deref().unwrap_or(urls::STRING))
            }
        }
    }
}

fn is_scalar(value: &Json) -> bool {
    matches!(value, Json::String(_) | Json::Number(_) | Json::Bool(_))
}

fn wrap(value: &Json) -> Option<Json> {
    is_scalar(value).then(|| Json::Array(vec![value.clone()]))
}

fn head(value: &Json) -> Option<Json> {
    value.as_array()?.first().cloned()
}

fn map_value(values: &BTreeMap<String, String>, value: &Json) -> Option<Json> {
    match value {
        Json::String(s) => Some(Json::String(values.get(s).unwrap_or(s).clone())),
        Json::Array(items) => Some(Json::Array(
            items
                .iter()
                .map(|item| match item {
                    Json::String(s) => Json::String(values.get(s).unwrap_or(s).clone()),
                    other => other.clone(),
                })
                .collect(),
        )),
        _ => None,
    }
}

/// A finite number as JSON. Whole numbers become integers, as JavaScript sees them.
fn number(f: f64) -> Option<Json> {
    if !f.is_finite() {
        return None;
    }
    if f.fract() == 0.0 && f.abs() <= MAX_SAFE_INTEGER as f64 {
        return Some(Json::Number(Number::from(f as i64)));
    }
    Number::from_f64(f).map(Json::Number)
}

/// A number the way JavaScript's `String(n)` writes it, for the range lenses
/// are specified for.
fn format_number(n: &Number) -> Option<String> {
    let f = n.as_f64()?;
    if !f.is_finite() {
        return None;
    }
    if f.fract() == 0.0 && f.abs() < 1e21 {
        return Some(format!("{}", f as i128));
    }
    Some(format!("{f}"))
}

fn is_integer_text(s: &str) -> bool {
    let digits = s.strip_prefix('-').unwrap_or(s);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

fn is_float_text(s: &str) -> bool {
    // -?\d+(\.\d+)?([eE][+-]?\d+)?
    let s = s.strip_prefix('-').unwrap_or(s);
    let (mantissa, exponent) = match s.find(['e', 'E']) {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    let (int, frac) = match mantissa.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (mantissa, None),
    };
    let digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
    if !digits(int) || frac.is_some_and(|f| !digits(f)) {
        return false;
    }
    match exponent {
        None => true,
        Some(e) => digits(e.strip_prefix(['+', '-']).unwrap_or(e)),
    }
}

fn convert(value: &Json, target: &str) -> Option<Json> {
    match (value, match_datatype(target)) {
        (Json::String(s), DataType::Integer) => {
            let t = s.trim();
            if !is_integer_text(t) {
                return None;
            }
            let n: i64 = t.parse().ok()?;
            (n.abs() <= MAX_SAFE_INTEGER).then(|| Json::Number(Number::from(n)))
        }
        (Json::String(s), DataType::Float) => {
            let t = s.trim();
            if !is_float_text(t) {
                return None;
            }
            number(t.parse::<f64>().ok()?)
        }
        (Json::String(s), DataType::Boolean) => match s.trim().to_lowercase().as_str() {
            "true" => Some(Json::Bool(true)),
            "false" => Some(Json::Bool(false)),
            _ => None,
        },
        (Json::Number(n), t) if is_text_type(&t) => format_number(n).map(Json::String),
        (Json::Bool(b), t) if is_text_type(&t) => Some(Json::String(b.to_string())),
        (Json::String(_), t) if is_text_type(&t) => Some(value.clone()),
        _ => None,
    }
}

fn is_text_type(t: &DataType) -> bool {
    matches!(
        t,
        DataType::String
            | DataType::Markdown
            | DataType::Slug
            | DataType::Date
            | DataType::Uri
            | DataType::AtomicUrl
    )
}

fn jcs_hash(context: &str, value: &Json) -> AtomicResult<String> {
    let canonical = serde_jcs::to_string(value)
        .map_err(|e| format!("Could not canonicalize lens identity: {e}"))?;
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(canonical.as_bytes());
    Ok(hasher.finalize().to_hex().to_string())
}

/// The `atomic:lens:{hex}` ID of a lens from `from` to `to` with this transform.
/// `from` and `to` are written in their `atomic:` form first.
pub fn lens_id(from: &str, to: &str, transform: &Json) -> AtomicResult<String> {
    if from.is_empty() || to.is_empty() {
        return Err("A lens needs a `from` and a `to` property".into());
    }
    let from = identifiers::canonicalize_scheme(from);
    let to = identifiers::canonicalize_scheme(to);
    if from == to {
        return Err("A lens cannot map a property onto itself".into());
    }
    let transform = Transform::parse(transform)?.to_json();
    let hex = jcs_hash(
        LENS_CONTEXT,
        &json!({"from": from, "to": to, "transform": transform}),
    )?;
    Ok(format!("{ATOMIC_LENS_PREFIX}{hex}"))
}

/// Check that `subject` (either prefix) is the ID of this lens.
pub fn verify_lens_id(subject: &str, from: &str, to: &str, transform: &Json) -> AtomicResult<()> {
    if !is_lens_id(subject) {
        return Err(format!("Not a lens identifier: '{subject}'").into());
    }
    let expected = lens_id(from, to, transform)?;
    if identifiers::canonicalize_scheme(subject) != expected {
        return Err(format!(
            "Lens ID mismatch: '{subject}' is not the hash of its from, to and transform (expected '{expected}')"
        )
        .into());
    }
    Ok(())
}

/// True for a well-formed `atomic:lens:` / `did:ad:lens:` identifier.
pub fn is_lens_id(subject: &str) -> bool {
    identifiers::lens_hash_hex(subject).is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// The `lensTransform` of a resource's propvals as JSON. Stored as a JSON
/// value, or as its text when the document carried no datatype tag.
fn transform_json(value: &Value) -> AtomicResult<Json> {
    match value {
        Value::Json(j) => Ok(j.clone()),
        other => Ok(serde_json::from_str(&other.to_string())?),
    }
}

/// Check a Lens ID against the `lensFrom`, `lensTo` and `lensTransform` in the
/// propvals of the resource it names. All three must be present.
pub fn verify_lens_genesis(subject: &str, propvals: &PropVals) -> AtomicResult<()> {
    let field = |prop: &str, name: &str| {
        propvals.get(prop).ok_or_else(|| {
            format!("Lens {subject} has no {name}; its ID is derived from lensFrom, lensTo and lensTransform")
        })
    };
    let from = field(urls::LENS_FROM, "lensFrom")?.to_string();
    let to = field(urls::LENS_TO, "lensTo")?.to_string();
    let transform = transform_json(field(urls::LENS_TRANSFORM, "lensTransform")?)?;
    field(urls::PARENT, "parent")?;
    verify_lens_id(subject, &from, &to, &transform)
}

/// A Lens's identity is hashed into its ID, so `lensFrom`, `lensTo` and
/// `lensTransform` (and its `parent`) can never change after creation.
pub fn check_lens_identity_unchanged(
    old: &crate::Resource,
    new: &crate::Resource,
) -> AtomicResult<()> {
    for (prop, name) in [
        (urls::PARENT, "parent"),
        (urls::LENS_FROM, "lensFrom"),
        (urls::LENS_TO, "lensTo"),
        (urls::LENS_TRANSFORM, "lensTransform"),
    ] {
        let norm = |r: &crate::Resource| {
            r.get(prop).ok().map(|v| match v {
                Value::Json(j) => serde_jcs::to_string(j).unwrap_or_default(),
                other => identifiers::canonicalize_scheme(&other.to_string()),
            })
        };
        if norm(old) != norm(new) {
            return Err(format!(
                "Cannot change the {name} of lens {}: a lens's identity cannot change",
                new.get_subject()
            )
            .into());
        }
    }
    Ok(())
}

/// One lens as the index holds it.
#[derive(Clone, Debug)]
pub struct LensEntry {
    /// `atomic:lens:{hex}`
    pub id: String,
    /// Canonical `lensFrom`.
    pub from: String,
    /// Canonical `lensTo`.
    pub to: String,
    pub transform: Transform,
    /// The ontology that owns `lensTo` (and this lens).
    pub parent: String,
    /// Datatype of `from`, to type a backward result.
    pub from_datatype: Option<DataType>,
    /// Datatype of `to`, to type a forward result.
    pub to_datatype: Option<DataType>,
}

/// Lenses by the properties they touch. Cheap to clone via `Arc`; the store
/// swaps in a new index when a Lens commit applies.
#[derive(Clone, Debug, Default)]
pub struct LensIndex {
    by_prop: HashMap<String, Vec<Arc<LensEntry>>>,
    ids: HashMap<String, Arc<LensEntry>>,
}

impl LensIndex {
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn get(&self, id: &str) -> Option<&Arc<LensEntry>> {
        self.ids.get(&identifiers::canonicalize_scheme(id))
    }

    /// Add a lens, replacing one with the same ID.
    pub fn insert(&mut self, entry: LensEntry) {
        self.remove(&entry.id);
        let entry = Arc::new(entry);
        for prop in [&entry.from, &entry.to] {
            self.by_prop
                .entry(prop.clone())
                .or_default()
                .push(entry.clone());
        }
        self.ids.insert(entry.id.clone(), entry);
    }

    pub fn remove(&mut self, id: &str) {
        let id = identifiers::canonicalize_scheme(id);
        if self.ids.remove(&id).is_none() {
            return;
        }
        for entries in self.by_prop.values_mut() {
            entries.retain(|e| e.id != id);
        }
        self.by_prop.retain(|_, entries| !entries.is_empty());
    }

    /// Lenses that touch this property.
    pub fn lenses_for(&self, prop: &str) -> &[Arc<LensEntry>] {
        self.by_prop
            .get(&identifiers::canonicalize_scheme(prop))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// True when a lens reads or writes this property.
    pub fn touches(&self, prop: &str) -> bool {
        !self.lenses_for(prop).is_empty()
    }

    /// Every property some lens reads or writes.
    pub fn properties(&self) -> impl Iterator<Item = &String> {
        self.by_prop.keys()
    }

    /// The values lenses derive from `own`, the properties a document really
    /// holds. One pass over `own`, no chaining: a derived value never feeds
    /// another lens. A real value always wins, and if two lenses derive the
    /// same property the one with the smaller ID wins.
    pub fn derive(&self, own: &BTreeMap<String, Json>) -> BTreeMap<String, (Json, Arc<LensEntry>)> {
        let mut derived: BTreeMap<String, (Json, Arc<LensEntry>)> = BTreeMap::new();
        if self.is_empty() {
            return derived;
        }
        let mut candidates: BTreeMap<&str, &Arc<LensEntry>> = BTreeMap::new();
        for prop in own.keys() {
            for lens in self.lenses_for(prop) {
                candidates.insert(&lens.id, lens);
            }
        }
        for lens in candidates.values() {
            let (has_from, has_to) = (own.get(&lens.from), own.get(&lens.to));
            let (target, value) = match (has_from, has_to) {
                (Some(v), None) => (&lens.to, lens.transform.forward(v)),
                (None, Some(v)) => (&lens.from, lens.transform.backward(v)),
                _ => continue,
            };
            let Some(value) = value else { continue };
            derived
                .entry(target.clone())
                .or_insert_with(|| (value, (*lens).clone()));
        }
        derived
    }

    /// [`Self::derive`] over a plain JSON map; returns the full map with the
    /// derived values added. This is what the shared fixture exercises.
    pub fn apply_json(&self, own: &BTreeMap<String, Json>) -> BTreeMap<String, Json> {
        let mut out = own.clone();
        for (prop, (value, _)) in self.derive(own) {
            out.entry(prop).or_insert(value);
        }
        out
    }

    /// Add derived values to a resource's propvals. Returns the properties
    /// that were derived.
    pub fn apply_propvals(&self, propvals: &mut PropVals) -> Vec<String> {
        if self.is_empty() {
            return Vec::new();
        }
        let canonical = |k: &str| identifiers::canonicalize_scheme(k);
        let mut own: BTreeMap<String, Json> = BTreeMap::new();
        for (key, value) in propvals.iter() {
            let key = canonical(key);
            if self.touches(&key) {
                if let Some(json) = value_to_json(value) {
                    own.insert(key, json);
                }
            }
        }
        let mut applied = Vec::new();
        for (prop, (json, lens)) in self.derive(&own) {
            if propvals.keys().any(|k| canonical(k) == prop) {
                continue;
            }
            let datatype = if prop == lens.to {
                lens.to_datatype.as_ref()
            } else {
                lens.from_datatype.as_ref()
            };
            if let Some(value) = json_to_value(&json, datatype) {
                propvals.insert(prop.clone(), value);
                applied.push(prop);
            }
        }
        applied
    }
}

/// A propval as the JSON a transform reads. `None` for values lenses do not touch.
pub fn value_to_json(value: &Value) -> Option<Json> {
    Some(match value {
        Value::String(s) | Value::Markdown(s) | Value::Slug(s) | Value::Date(s) | Value::Uri(s) => {
            Json::String(s.clone())
        }
        Value::AtomicUrl(s) => Json::String(s.to_string()),
        Value::Integer(i) | Value::Timestamp(i) => Json::Number(Number::from(*i)),
        Value::Float(f) => number(*f)?,
        Value::Boolean(b) => Json::Bool(*b),
        Value::ResourceArray(items) => Json::Array(
            items
                .iter()
                .map(|item| match item {
                    SubResource::Subject(s) => Some(Json::String(s.to_string())),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()?,
        ),
        _ => return None,
    })
}

/// A transform result as a propval of `datatype`. Without a datatype the
/// JSON shape decides.
pub fn json_to_value(json: &Json, datatype: Option<&DataType>) -> Option<Value> {
    let datatype = match datatype {
        Some(DataType::Unsupported(_)) | None => match json {
            Json::String(_) => DataType::String,
            Json::Bool(_) => DataType::Boolean,
            Json::Array(_) => DataType::ResourceArray,
            Json::Number(n) if n.is_i64() => DataType::Integer,
            Json::Number(_) => DataType::Float,
            _ => return None,
        },
        Some(other) => other.clone(),
    };
    match (json, datatype) {
        (Json::String(s), DataType::String) => Some(Value::String(s.clone())),
        (Json::String(s), DataType::Markdown) => Some(Value::Markdown(s.clone())),
        (Json::String(s), DataType::Slug) => Some(Value::Slug(s.clone())),
        (Json::String(s), DataType::Date) => Some(Value::Date(s.clone())),
        (Json::String(s), DataType::Uri) => Some(Value::Uri(s.clone())),
        (Json::String(s), DataType::AtomicUrl) => Some(Value::AtomicUrl(s.as_str().into())),
        (Json::Number(n), DataType::Integer) => n
            .as_i64()
            .or_else(|| n.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64))
            .map(Value::Integer),
        (Json::Number(n), DataType::Timestamp) => n.as_i64().map(Value::Timestamp),
        (Json::Number(n), DataType::Float) => n.as_f64().map(Value::Float),
        (Json::Bool(b), DataType::Boolean) => Some(Value::Boolean(*b)),
        (Json::Array(items), DataType::ResourceArray) => items
            .iter()
            .map(|item| item.as_str().map(|s| SubResource::Subject(s.into())))
            .collect::<Option<Vec<_>>>()
            .map(Value::ResourceArray),
        _ => None,
    }
}

/// Build the index entry for a Lens resource.
///
/// The lens only counts when its ID matches its content and its `parent` is
/// the parent of the property it writes (`lensTo`): a lens never applies across
/// an ontology it does not own. That needs `lensTo` to be in the store; an
/// error here means "not (yet) active", never a rejected commit.
pub async fn build_entry(
    store: &impl crate::Storelike,
    lens: &crate::Resource,
) -> AtomicResult<LensEntry> {
    let subject = identifiers::canonicalize_scheme(&lens.get_subject().pure_id());
    verify_lens_genesis(&subject, lens.get_propvals())?;
    let canon = |prop: &str| -> AtomicResult<String> {
        Ok(identifiers::canonicalize_scheme(
            &lens.get(prop)?.to_string(),
        ))
    };
    let (from, to, parent) = (
        canon(urls::LENS_FROM)?,
        canon(urls::LENS_TO)?,
        canon(urls::PARENT)?,
    );
    let transform = Transform::parse(&transform_json(lens.get(urls::LENS_TRANSFORM)?)?)?;

    let property = |subject: String| async move {
        let subject: crate::Subject = subject.as_str().into();
        if !store.has_stored_resource(&subject) {
            return Err(format!("Property {subject} is not in this store").into());
        }
        store.get_resource(&subject).await
    };
    let to_resource = property(to.clone()).await?;
    let to_parent = identifiers::canonicalize_scheme(&to_resource.get(urls::PARENT)?.to_string());
    if to_parent != parent {
        return Err(format!(
            "Lens {subject} belongs to {parent}, but {to} belongs to {to_parent}: a lens only applies within the ontology that owns its target"
        )
        .into());
    }
    let datatype_of = |r: &crate::Resource| {
        r.get(urls::DATATYPE_PROP)
            .ok()
            .map(|v| match_datatype(&v.to_string()))
    };
    let from_datatype = match property(from.clone()).await {
        Ok(r) => datatype_of(&r),
        Err(_) => None,
    };
    Ok(LensEntry {
        id: subject,
        from,
        to,
        transform,
        parent,
        from_datatype,
        to_datatype: datatype_of(&to_resource),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "atomic:prop:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "atomic:prop:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn fixed_vectors() {
        for (from, to, transform, want) in lens_vectors() {
            assert_eq!(lens_id(from, to, &transform).unwrap(), want, "{from} {to}");
        }
    }

    /// The vectors listed in docs/src/schema/lenses.md.
    fn lens_vectors() -> Vec<(&'static str, &'static str, Json, &'static str)> {
        vec![
            (A, B, json!({"op": "rename"}), VECTOR_RENAME),
            (
                &*A.replace("atomic:", "did:ad:").leak(),
                B,
                json!({"op": "rename"}),
                VECTOR_RENAME,
            ),
            (A, B, json!({"op": "wrap"}), VECTOR_WRAP),
            (
                A,
                B,
                json!({"op": "map", "values": {"todo": "open", "done": "closed"}}),
                VECTOR_MAP,
            ),
            (
                A,
                B,
                json!({"op": "convert", "to": urls::INTEGER}),
                VECTOR_CONVERT,
            ),
        ]
    }

    const VECTOR_RENAME: &str =
        "atomic:lens:ba1b06696c9786de8f0b78189d69c3aa84d59181b8eba91b7678de5959d07fcb";
    const VECTOR_WRAP: &str =
        "atomic:lens:0e8670cccd962e1352793444a88fb841c27c39b7e74bce6b58fafbaea1056825";
    const VECTOR_MAP: &str =
        "atomic:lens:cfbe882e5669613c8eed6dfdcaaeda204b2a5dd4d264528875911d394d2d80a5";
    const VECTOR_CONVERT: &str =
        "atomic:lens:0201a75d08b29edddb2131fd8143349db2f8f1a3a2ab2d605a0aea9ba9262170";

    #[test]
    fn rejects_bad_input() {
        let rename = json!({"op": "rename"});
        assert!(lens_id(A, A, &rename).is_err());
        assert!(lens_id("", B, &rename).is_err());
        assert!(lens_id(A, B, &json!({"op": "teleport"})).is_err());
        assert!(lens_id(A, B, &json!({"op": "rename", "extra": 1})).is_err());
        assert!(lens_id(A, B, &json!({"op": "convert"})).is_err());
        assert!(lens_id(
            A,
            B,
            &json!({"op": "convert", "to": "https://example.com/x"})
        )
        .is_err());
        assert!(lens_id(A, B, &json!({"op": "map", "values": {"a": 1}})).is_err());
    }

    #[test]
    fn verify_accepts_both_prefixes_and_rejects_mismatch() {
        let rename = json!({"op": "rename"});
        let id = lens_id(A, B, &rename).unwrap();
        assert!(is_lens_id(&id));
        verify_lens_id(&id, A, B, &rename).unwrap();
        verify_lens_id(&id.replace("atomic:", "did:ad:"), A, B, &rename).unwrap();
        assert!(verify_lens_id(&id, B, A, &rename).is_err());
        assert!(verify_lens_id(&id, A, B, &json!({"op": "wrap"})).is_err());
        assert!(!is_lens_id("atomic:lens:"));
        assert!(!is_lens_id("atomic:lens:ABC"));
    }

    /// Runs the shared fixture `lib/tests/fixtures/lenses.json`.
    #[test]
    fn shared_fixture() {
        let fixture: Json =
            serde_json::from_str(include_str!("../tests/fixtures/lenses.json")).unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let mut index = LensIndex::default();
            for (n, lens) in case["lenses"].as_array().unwrap().iter().enumerate() {
                let transform = Transform::parse(&lens["transform"]).unwrap();
                let datatype = |key: &str| lens.get(key).and_then(Json::as_str).map(match_datatype);
                let from = lens["from"].as_str().unwrap().to_string();
                let to = lens["to"].as_str().unwrap().to_string();
                index.insert(LensEntry {
                    id: format!("atomic:lens:{n:064}"),
                    from,
                    to,
                    transform,
                    parent: "atomic:ontology".into(),
                    from_datatype: datatype("fromDatatype"),
                    to_datatype: datatype("toDatatype"),
                });
            }
            let doc: BTreeMap<String, Json> = serde_json::from_value(case["doc"].clone()).unwrap();
            let expected: BTreeMap<String, Json> =
                serde_json::from_value(case["expected"].clone()).unwrap();

            // The JSON path.
            assert_eq!(
                normalize(index.apply_json(&doc)),
                normalize(expected.clone()),
                "{name} (json)"
            );

            // The propvals path: the same case through `Value`s.
            let datatypes: HashMap<String, DataType> = index
                .by_prop
                .values()
                .flatten()
                .flat_map(|l| {
                    [
                        l.from_datatype.clone().map(|d| (l.from.clone(), d)),
                        l.to_datatype.clone().map(|d| (l.to.clone(), d)),
                    ]
                })
                .flatten()
                .collect();
            let mut propvals = PropVals::new();
            for (prop, json) in &doc {
                propvals.insert(
                    prop.clone(),
                    json_to_value(json, datatypes.get(prop)).unwrap_or_else(|| {
                        panic!("{name}: cannot make a Value of {json} for {prop}")
                    }),
                );
            }
            index.apply_propvals(&mut propvals);
            let got: BTreeMap<String, Json> = propvals
                .iter()
                .filter_map(|(k, v)| value_to_json(v).map(|j| (k.clone(), j)))
                .collect();
            assert_eq!(normalize(got), normalize(expected), "{name} (propvals)");
        }
    }

    /// Numbers compare as floats: `2` and `2.0` are one value to JavaScript.
    fn normalize(map: BTreeMap<String, Json>) -> BTreeMap<String, Json> {
        fn walk(v: Json) -> Json {
            match v {
                Json::Number(n) => number(n.as_f64().unwrap()).unwrap(),
                Json::Array(items) => Json::Array(items.into_iter().map(walk).collect()),
                other => other,
            }
        }
        map.into_iter().map(|(k, v)| (k, walk(v))).collect()
    }

    #[test]
    fn real_values_win_and_derived_do_not_chain() {
        let mut index = LensIndex::default();
        for (n, (from, to)) in [(A, B), (B, "atomic:prop:c")].into_iter().enumerate() {
            index.insert(LensEntry {
                id: format!("atomic:lens:{n}"),
                from: from.into(),
                to: to.into(),
                transform: Transform::Rename,
                parent: "p".into(),
                from_datatype: None,
                to_datatype: None,
            });
        }
        let own = BTreeMap::from([(A.to_string(), json!("x"))]);
        let out = index.apply_json(&own);
        assert_eq!(out.get(B), Some(&json!("x")));
        assert!(!out.contains_key("atomic:prop:c"), "no chaining");
    }
}
