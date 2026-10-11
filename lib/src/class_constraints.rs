//! Value constraints that live on a Class, not on its Properties.
//!
//! A Class has a `constraints` map: property subject to an object of JSON
//! Schema keywords (see `docs/src/schema/classes.md`). The TypeScript twin is
//! `browser/lib/src/class-constraints.ts`; both run the cases in
//! `lib/tests/fixtures/class-constraints.json`, so change them together.

use std::collections::BTreeMap;

use regex::Regex;
use serde_json::Value as Json;

use crate::{
    errors::AtomicResult, identifiers::canonicalize_scheme, storelike::Storelike, urls,
    values::SubResource, Resource, Value,
};

/// Every keyword a constraint may use. Anything else is rejected on write.
pub const KEYWORDS: [&str; 18] = [
    "enum",
    "const",
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "anyOf",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
    "pattern",
    "class",
];

/// How deep schemas may nest (`properties`, `items`, `anyOf`, ...). A
/// constraint nested deeper is rejected when it is parsed.
pub const MAX_DEPTH: usize = 16;

const TYPES: [&str; 7] = [
    "string", "number", "integer", "boolean", "null", "object", "array",
];

/// `additionalProperties`: `false` forbids unlisted keys, a schema checks them.
/// `true` is the default and changes nothing.
#[derive(Clone, Debug)]
pub enum AdditionalProperties {
    Allowed(bool),
    Schema(Box<Constraint>),
}

/// The constraints on one property of one class. Below the top level the same
/// struct describes a nested JSON Schema (`properties`, `items`, `anyOf`).
#[derive(Clone, Debug, Default)]
pub struct Constraint {
    pub enum_values: Option<Vec<Json>>,
    pub const_value: Option<Json>,
    /// Allowed JSON types, any of them. `"null"` makes a value nullable.
    pub types: Option<Vec<String>>,
    pub properties: Option<BTreeMap<String, Constraint>>,
    pub required: Option<Vec<String>>,
    pub additional_properties: Option<AdditionalProperties>,
    pub items: Option<Box<Constraint>>,
    pub any_of: Option<Vec<Constraint>>,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
    pub exclusive_minimum: Option<f64>,
    pub exclusive_maximum: Option<f64>,
    pub min_length: Option<u64>,
    pub max_length: Option<u64>,
    pub min_items: Option<u64>,
    pub max_items: Option<u64>,
    pub pattern: Option<Regex>,
    /// Subject of the class a link should point to. For pickers and forms,
    /// never checked at write time.
    pub class: Option<String>,
}

/// A class's constraints, keyed by canonical property subject.
pub type Constraints = BTreeMap<String, Constraint>;

/// A value broke a constraint.
#[derive(Clone, Debug, PartialEq)]
pub struct ConstraintError {
    /// The JSON Schema keyword that failed.
    pub keyword: &'static str,
    pub detail: String,
    /// JSON pointer to the failing value inside the property's value. Empty
    /// for the value itself, `/pad/tune` for a nested one.
    pub path: String,
}

impl std::fmt::Display for ConstraintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.path.is_empty() {
            write!(f, "{}: {}", self.keyword, self.detail)
        } else {
            write!(f, "{} at {}: {}", self.keyword, self.path, self.detail)
        }
    }
}

impl std::error::Error for ConstraintError {}

fn number(keyword: &str, v: &Json) -> AtomicResult<f64> {
    v.as_f64()
        .ok_or_else(|| format!("Constraint `{keyword}` must be a number, got {v}").into())
}

fn count(keyword: &str, v: &Json) -> AtomicResult<u64> {
    v.as_u64().ok_or_else(|| {
        format!("Constraint `{keyword}` must be a non-negative integer, got {v}").into()
    })
}

/// Parses one constraint object, rejecting unknown keywords and wrong types.
pub fn parse_constraint(json: &Json) -> AtomicResult<Constraint> {
    parse_at(json, 0)
}

fn nested(keyword: &str, key: &str, v: &Json, depth: usize) -> AtomicResult<Constraint> {
    parse_at(v, depth + 1).map_err(|e| format!("in `{keyword}`{key}: {e}").into())
}

fn parse_at(json: &Json, depth: usize) -> AtomicResult<Constraint> {
    if depth > MAX_DEPTH {
        return Err(format!("Constraints nest deeper than {MAX_DEPTH} levels").into());
    }
    let obj = json
        .as_object()
        .ok_or_else(|| format!("A constraint must be a JSON object, got {json}"))?;
    let mut c = Constraint::default();

    for (keyword, v) in obj {
        match keyword.as_str() {
            "enum" => {
                let arr = v
                    .as_array()
                    .ok_or_else(|| format!("Constraint `enum` must be an array, got {v}"))?;
                c.enum_values = Some(arr.clone());
            }
            "minimum" => c.minimum = Some(number(keyword, v)?),
            "maximum" => c.maximum = Some(number(keyword, v)?),
            "exclusiveMinimum" => c.exclusive_minimum = Some(number(keyword, v)?),
            "exclusiveMaximum" => c.exclusive_maximum = Some(number(keyword, v)?),
            "minLength" => c.min_length = Some(count(keyword, v)?),
            "maxLength" => c.max_length = Some(count(keyword, v)?),
            "minItems" => c.min_items = Some(count(keyword, v)?),
            "maxItems" => c.max_items = Some(count(keyword, v)?),
            "pattern" => {
                let src = v
                    .as_str()
                    .ok_or_else(|| format!("Constraint `pattern` must be a string, got {v}"))?;
                c.pattern = Some(
                    Regex::new(src)
                        .map_err(|e| format!("Constraint `pattern` is not a valid regex: {e}"))?,
                );
            }
            "class" => {
                if depth > 0 {
                    return Err(
                        "Constraint `class` only applies to a property, not inside a nested schema"
                            .into(),
                    );
                }
                let s = v
                    .as_str()
                    .ok_or_else(|| format!("Constraint `class` must be a string, got {v}"))?;
                c.class = Some(canonicalize_scheme(s));
            }
            "const" => c.const_value = Some(v.clone()),
            "type" => {
                let names: Vec<&Json> = match v {
                    Json::Array(a) => a.iter().collect(),
                    single => vec![single],
                };
                let mut types = Vec::new();
                for name in names {
                    match name.as_str().filter(|n| TYPES.contains(n)) {
                        Some(n) => {
                            if !types.iter().any(|t| t == n) {
                                types.push(n.to_string());
                            }
                        }
                        None => {
                            return Err(format!(
                                "Constraint `type` must be one of {} or an array of them, got {v}",
                                TYPES.join(", ")
                            )
                            .into())
                        }
                    }
                }
                if types.is_empty() {
                    return Err("Constraint `type` cannot be an empty array".into());
                }
                c.types = Some(types);
            }
            "properties" => {
                let map = v
                    .as_object()
                    .ok_or_else(|| format!("Constraint `properties` must be an object, got {v}"))?;
                let mut out = BTreeMap::new();
                for (name, schema) in map {
                    out.insert(
                        name.clone(),
                        nested("properties", &format!(" for \"{name}\""), schema, depth)?,
                    );
                }
                c.properties = Some(out);
            }
            "required" => {
                let arr = v
                    .as_array()
                    .ok_or_else(|| format!("Constraint `required` must be an array, got {v}"))?;
                c.required = Some(
                    arr.iter()
                        .map(|n| {
                            n.as_str().map(str::to_string).ok_or_else(|| {
                                format!("Constraint `required` must hold strings, got {n}")
                            })
                        })
                        .collect::<Result<_, _>>()?,
                );
            }
            "additionalProperties" => {
                c.additional_properties = Some(match v {
                    Json::Bool(b) => AdditionalProperties::Allowed(*b),
                    Json::Object(_) => {
                        AdditionalProperties::Schema(Box::new(nested("additionalProperties", "", v, depth)?))
                    }
                    other => {
                        return Err(format!(
                            "Constraint `additionalProperties` must be a boolean or a schema, got {other}"
                        )
                        .into())
                    }
                });
            }
            "items" => c.items = Some(Box::new(nested("items", "", v, depth)?)),
            "anyOf" => {
                let arr = v.as_array().filter(|a| !a.is_empty()).ok_or_else(|| {
                    format!("Constraint `anyOf` must be a non-empty array, got {v}")
                })?;
                c.any_of = Some(
                    arr.iter()
                        .map(|b| nested("anyOf", "", b, depth))
                        .collect::<AtomicResult<_>>()?,
                );
            }
            other => {
                return Err(format!(
                    "Unknown constraint keyword `{other}`. Allowed: {}",
                    KEYWORDS.join(", ")
                )
                .into())
            }
        }
    }

    Ok(c)
}

/// Parses a whole `constraints` map. Property keys are canonicalized
/// (`did:ad:` becomes `atomic:`), HTTP subjects are kept as they are.
pub fn parse_constraints(json: &Json) -> AtomicResult<Constraints> {
    let obj = json
        .as_object()
        .ok_or_else(|| format!("`constraints` must be a JSON object, got {json}"))?;
    let mut out = Constraints::new();

    for (prop, constraint) in obj {
        let parsed = parse_constraint(constraint)
            .map_err(|e| format!("Invalid constraint for {prop}: {e}"))?;
        out.insert(canonicalize_scheme(prop), parsed);
    }

    Ok(out)
}

/// Reads the `constraints` value of a Class resource, if it has one.
/// Accepts the JSON value itself or a JSON string of it.
pub fn constraints_of(class: &Resource) -> AtomicResult<Option<Constraints>> {
    let Ok(value) = class.get(urls::CONSTRAINTS) else {
        return Ok(None);
    };
    let json = match value {
        Value::Json(j) => j.clone(),
        Value::String(s) | Value::Markdown(s) => {
            serde_json::from_str(s).map_err(|e| format!("`constraints` is not valid JSON: {e}"))?
        }
        other => return Err(format!("`constraints` must be JSON, got {other}").into()),
    };
    Ok(Some(parse_constraints(&json)?))
}

const LEGACY_MIN: &str = "https://atomicdata.dev/properties/min";
const LEGACY_MAX: &str = "https://atomicdata.dev/properties/max";

impl Constraint {
    /// A value has to satisfy both: lower bounds take the larger value, upper
    /// bounds the smaller, `enum`s intersect. A pattern or linked class cannot
    /// be combined, so `self` wins. Twin of `tighten` in
    /// `browser/lib/src/effective-constraint.ts`.
    pub fn tighten(&self, other: &Constraint) -> Constraint {
        fn lower<T: PartialOrd + Copy>(a: Option<T>, b: Option<T>) -> Option<T> {
            match (a, b) {
                (Some(x), Some(y)) => Some(if y > x { y } else { x }),
                (x, None) => x,
                (None, y) => y,
            }
        }
        fn upper<T: PartialOrd + Copy>(a: Option<T>, b: Option<T>) -> Option<T> {
            match (a, b) {
                (Some(x), Some(y)) => Some(if y < x { y } else { x }),
                (x, None) => x,
                (None, y) => y,
            }
        }
        let enum_values = match (&self.enum_values, &other.enum_values) {
            (Some(a), Some(b)) => Some(
                a.iter()
                    .filter(|x| b.iter().any(|y| json_eq(x, y)))
                    .cloned()
                    .collect(),
            ),
            (Some(a), None) => Some(a.clone()),
            (None, b) => b.clone(),
        };
        Constraint {
            enum_values,
            minimum: lower(self.minimum, other.minimum),
            maximum: upper(self.maximum, other.maximum),
            exclusive_minimum: lower(self.exclusive_minimum, other.exclusive_minimum),
            exclusive_maximum: upper(self.exclusive_maximum, other.exclusive_maximum),
            min_length: lower(self.min_length, other.min_length),
            max_length: upper(self.max_length, other.max_length),
            min_items: lower(self.min_items, other.min_items),
            max_items: upper(self.max_items, other.max_items),
            pattern: self.pattern.clone().or_else(|| other.pattern.clone()),
            class: self.class.clone().or_else(|| other.class.clone()),
            // Nested schemas cannot be combined either: `self` wins.
            const_value: self
                .const_value
                .clone()
                .or_else(|| other.const_value.clone()),
            types: self.types.clone().or_else(|| other.types.clone()),
            properties: self.properties.clone().or_else(|| other.properties.clone()),
            required: self.required.clone().or_else(|| other.required.clone()),
            additional_properties: self
                .additional_properties
                .clone()
                .or_else(|| other.additional_properties.clone()),
            items: self.items.clone().or_else(|| other.items.clone()),
            any_of: self.any_of.clone().or_else(|| other.any_of.clone()),
        }
    }

    /// `self` with every keyword `top` sets replacing the one in `self`.
    pub fn overlay(&self, top: &Constraint) -> Constraint {
        Constraint {
            enum_values: top.enum_values.clone().or_else(|| self.enum_values.clone()),
            minimum: top.minimum.or(self.minimum),
            maximum: top.maximum.or(self.maximum),
            exclusive_minimum: top.exclusive_minimum.or(self.exclusive_minimum),
            exclusive_maximum: top.exclusive_maximum.or(self.exclusive_maximum),
            min_length: top.min_length.or(self.min_length),
            max_length: top.max_length.or(self.max_length),
            min_items: top.min_items.or(self.min_items),
            max_items: top.max_items.or(self.max_items),
            pattern: top.pattern.clone().or_else(|| self.pattern.clone()),
            class: top.class.clone().or_else(|| self.class.clone()),
            const_value: top.const_value.clone().or_else(|| self.const_value.clone()),
            types: top.types.clone().or_else(|| self.types.clone()),
            properties: top.properties.clone().or_else(|| self.properties.clone()),
            required: top.required.clone().or_else(|| self.required.clone()),
            additional_properties: top
                .additional_properties
                .clone()
                .or_else(|| self.additional_properties.clone()),
            items: top.items.clone().or_else(|| self.items.clone()),
            any_of: top.any_of.clone().or_else(|| self.any_of.clone()),
        }
    }

    /// The constraint as JSON Schema keywords, the inverse of
    /// [`parse_constraint`].
    pub fn to_json(&self) -> Json {
        let mut o = serde_json::Map::new();
        if let Some(v) = &self.enum_values {
            o.insert("enum".into(), Json::Array(v.clone()));
        }
        let num = |v: f64| {
            if v.fract() == 0.0 && v.abs() < 9e15 {
                Json::from(v as i64)
            } else {
                serde_json::Number::from_f64(v).map_or(Json::Null, Json::Number)
            }
        };
        for (k, v) in [
            ("minimum", self.minimum),
            ("maximum", self.maximum),
            ("exclusiveMinimum", self.exclusive_minimum),
            ("exclusiveMaximum", self.exclusive_maximum),
        ] {
            if let Some(v) = v {
                o.insert(k.into(), num(v));
            }
        }
        for (k, v) in [
            ("minLength", self.min_length),
            ("maxLength", self.max_length),
            ("minItems", self.min_items),
            ("maxItems", self.max_items),
        ] {
            if let Some(v) = v {
                o.insert(k.into(), Json::from(v));
            }
        }
        if let Some(re) = &self.pattern {
            o.insert("pattern".into(), Json::String(re.as_str().to_string()));
        }
        if let Some(c) = &self.class {
            o.insert("class".into(), Json::String(c.clone()));
        }
        if let Some(v) = &self.const_value {
            o.insert("const".into(), v.clone());
        }
        if let Some(types) = &self.types {
            o.insert(
                "type".into(),
                match types.as_slice() {
                    [one] => Json::String(one.clone()),
                    many => Json::Array(many.iter().cloned().map(Json::String).collect()),
                },
            );
        }
        if let Some(props) = &self.properties {
            o.insert(
                "properties".into(),
                Json::Object(
                    props
                        .iter()
                        .map(|(k, v)| (k.clone(), v.to_json()))
                        .collect(),
                ),
            );
        }
        if let Some(required) = &self.required {
            o.insert(
                "required".into(),
                Json::Array(required.iter().cloned().map(Json::String).collect()),
            );
        }
        match &self.additional_properties {
            Some(AdditionalProperties::Allowed(b)) => {
                o.insert("additionalProperties".into(), Json::Bool(*b));
            }
            Some(AdditionalProperties::Schema(c)) => {
                o.insert("additionalProperties".into(), c.to_json());
            }
            None => {}
        }
        if let Some(items) = &self.items {
            o.insert("items".into(), items.to_json());
        }
        if let Some(branches) = &self.any_of {
            o.insert(
                "anyOf".into(),
                Json::Array(branches.iter().map(Constraint::to_json).collect()),
            );
        }
        Json::Object(o)
    }
}

/// What the legacy Property fields (`allowsOnly`, `classtype`, `min`, `max`)
/// say, in class-constraint vocabulary. The fallback for data that predates
/// the class map.
pub fn legacy_constraint(property: &Resource) -> Constraint {
    let mut c = Constraint::default();

    if let Some(subjects) = property
        .get(urls::ALLOWS_ONLY)
        .ok()
        .and_then(|v| v.to_subjects(None).ok())
        .filter(|s| !s.is_empty())
    {
        c.enum_values = Some(subjects.into_iter().map(Json::String).collect());
    }
    if let Some(class) = property
        .get(urls::CLASSTYPE_PROP)
        .ok()
        .map(|v| v.to_string())
        .filter(|s| !s.is_empty())
    {
        c.class = Some(canonicalize_scheme(&class));
    }

    let datatype = property
        .get(urls::DATATYPE_PROP)
        .map(|v| v.to_string())
        .unwrap_or_default();
    let read = |prop: &str| {
        property
            .get(prop)
            .ok()
            .and_then(|v| v.to_string().parse::<f64>().ok())
            .filter(|n| n.is_finite())
    };
    let (min, max) = (read(LEGACY_MIN), read(LEGACY_MAX));
    let count = |n: Option<f64>| n.filter(|n| *n >= 0.0).map(|n| n.trunc() as u64);

    if datatype == urls::RESOURCE_ARRAY {
        c.min_items = count(min);
        c.max_items = count(max);
    } else if [urls::INTEGER, urls::FLOAT, urls::TIMESTAMP].contains(&datatype.as_str()) {
        c.minimum = min;
        c.maximum = max;
    } else if [urls::STRING, urls::MARKDOWN, urls::SLUG, urls::URI].contains(&datatype.as_str()) {
        c.min_length = count(min);
        c.max_length = count(max);
    }

    c
}

/// The constraint that applies to `property` for a row that is an instance of
/// all of `class_subjects`: the class maps are tightened together, then laid
/// over the Property's legacy fields per keyword (a keyword no class sets
/// falls back to the Property). Classes that are missing or whose map does not
/// parse are skipped. Twin of `getEffectiveConstraint` in
/// `browser/lib/src/effective-constraint.ts`.
pub async fn effective_constraint(
    store: &impl Storelike,
    class_subjects: &[String],
    property: &str,
) -> Constraint {
    let key = canonicalize_scheme(property);
    let mut from_classes: Option<Constraint> = None;

    for class_subject in class_subjects {
        let Ok(class) = store.get_resource(&class_subject.as_str().into()).await else {
            continue;
        };
        let Ok(Some(mut map)) = constraints_of(&class) else {
            continue;
        };
        if let Some(entry) = map.remove(&key) {
            from_classes = Some(match from_classes {
                Some(prev) => prev.tighten(&entry),
                None => entry,
            });
        }
    }

    let legacy = match store.get_resource(&property.into()).await {
        Ok(p) => legacy_constraint(&p),
        Err(_) => Constraint::default(),
    };

    match from_classes {
        Some(top) => legacy.overlay(&top),
        None => legacy,
    }
}

/// Rejects a Class resource whose `constraints` map would not parse.
/// A no-op for resources without one.
pub fn validate_constraints_prop(resource: &Resource) -> AtomicResult<()> {
    constraints_of(resource)
        .map(|_| ())
        .map_err(|e| format!("Invalid constraints on {}: {e}", resource.get_subject()).into())
}

fn canonical_json(v: &Json) -> Json {
    match v {
        Json::String(s) => Json::String(canonicalize_scheme(s)),
        other => other.clone(),
    }
}

fn json_eq(a: &Json, b: &Json) -> bool {
    match (a, b) {
        (Json::Number(x), Json::Number(y)) => x.as_f64() == y.as_f64(),
        (Json::Array(x), Json::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(a, b)| json_eq(a, b))
        }
        (Json::Object(x), Json::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, a)| y.get(k).is_some_and(|b| json_eq(a, b)))
        }
        _ => canonical_json(a) == canonical_json(b),
    }
}

fn pointer_of(path: &[String]) -> String {
    path.iter()
        .map(|s| format!("/{}", s.replace('~', "~0").replace('/', "~1")))
        .collect()
}

fn type_matches(name: &str, value: &Json) -> bool {
    match (name, value) {
        ("string", Json::String(_))
        | ("boolean", Json::Bool(_))
        | ("null", Json::Null)
        | ("object", Json::Object(_))
        | ("array", Json::Array(_))
        | ("number", Json::Number(_)) => true,
        ("integer", Json::Number(n)) => {
            n.is_i64()
                || n.is_u64()
                || n.as_f64()
                    .is_some_and(|f| f.is_finite() && f.fract() == 0.0)
        }
        _ => false,
    }
}

fn type_name_of(value: &Json) -> &'static str {
    match value {
        Json::Null => "null",
        Json::Bool(_) => "boolean",
        Json::Number(_) => "number",
        Json::String(_) => "string",
        Json::Array(_) => "array",
        Json::Object(_) => "object",
    }
}

/// Checks a JSON value. A keyword that does not apply to the value's type is
/// ignored, as in JSON Schema. For a top-level array, `enum` applies to every
/// item; below the top level it applies to the value as a whole, as in JSON
/// Schema. Nested schemas (`properties`, `items`, `anyOf`) are checked
/// recursively and an error carries the JSON pointer of the failing value.
pub fn check_json(c: &Constraint, value: &Json) -> Result<(), ConstraintError> {
    check_at(c, value, &mut Vec::new(), 0)
}

fn check_at(
    c: &Constraint,
    value: &Json,
    path: &mut Vec<String>,
    depth: usize,
) -> Result<(), ConstraintError> {
    let fail = |path: &[String], keyword: &'static str, detail: String| {
        Err(ConstraintError {
            keyword,
            detail,
            path: pointer_of(path),
        })
    };

    if depth > MAX_DEPTH {
        return fail(
            path,
            "depth",
            format!("constraints nest deeper than {MAX_DEPTH} levels"),
        );
    }

    if let Some(allowed) = &c.enum_values {
        let items: Vec<&Json> = match value {
            Json::Array(a) if depth == 0 => a.iter().collect(),
            single => vec![single],
        };
        for item in items {
            if !allowed.iter().any(|a| json_eq(a, item)) {
                return fail(
                    path,
                    "enum",
                    format!("{item} is not one of {}", Json::Array(allowed.clone())),
                );
            }
        }
    }

    if let Some(expected) = &c.const_value {
        if !json_eq(expected, value) {
            return fail(path, "const", format!("{value} is not {expected}"));
        }
    }

    if let Some(types) = &c.types {
        if !types.iter().any(|t| type_matches(t, value)) {
            return fail(
                path,
                "type",
                format!(
                    "{} is not of type {}",
                    type_name_of(value),
                    types.join(" or ")
                ),
            );
        }
    }

    match value {
        Json::Number(n) => {
            let Some(n) = n.as_f64() else { return Ok(()) };
            if let Some(m) = c.minimum {
                if n < m {
                    return fail(path, "minimum", format!("{n} is below {m}"));
                }
            }
            if let Some(m) = c.maximum {
                if n > m {
                    return fail(path, "maximum", format!("{n} is above {m}"));
                }
            }
            if let Some(m) = c.exclusive_minimum {
                if n <= m {
                    return fail(path, "exclusiveMinimum", format!("{n} is not above {m}"));
                }
            }
            if let Some(m) = c.exclusive_maximum {
                if n >= m {
                    return fail(path, "exclusiveMaximum", format!("{n} is not below {m}"));
                }
            }
        }
        Json::String(s) => {
            let len = s.chars().count() as u64;
            if let Some(m) = c.min_length {
                if len < m {
                    return fail(path, "minLength", format!("length {len} is below {m}"));
                }
            }
            if let Some(m) = c.max_length {
                if len > m {
                    return fail(path, "maxLength", format!("length {len} is above {m}"));
                }
            }
            if let Some(re) = &c.pattern {
                if !re.is_match(s) {
                    return fail(
                        path,
                        "pattern",
                        format!("{s:?} does not match {}", re.as_str()),
                    );
                }
            }
        }
        Json::Array(a) => {
            let len = a.len() as u64;
            if let Some(m) = c.min_items {
                if len < m {
                    return fail(path, "minItems", format!("{len} items is below {m}"));
                }
            }
            if let Some(m) = c.max_items {
                if len > m {
                    return fail(path, "maxItems", format!("{len} items is above {m}"));
                }
            }
            if let Some(items) = &c.items {
                for (i, item) in a.iter().enumerate() {
                    path.push(i.to_string());
                    check_at(items, item, path, depth + 1)?;
                    path.pop();
                }
            }
        }
        Json::Object(o) => {
            for name in c.required.iter().flatten() {
                if !o.contains_key(name) {
                    return fail(path, "required", format!("missing property {name:?}"));
                }
            }
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            for key in keys {
                let listed = c.properties.as_ref().and_then(|p| p.get(key));
                let schema = match (listed, &c.additional_properties) {
                    (Some(schema), _) => Some(schema),
                    (None, Some(AdditionalProperties::Allowed(false))) => {
                        path.push(key.clone());
                        let err = fail(
                            path,
                            "additionalProperties",
                            "property is not allowed".into(),
                        );
                        path.pop();
                        return err;
                    }
                    (None, Some(AdditionalProperties::Schema(schema))) => Some(schema.as_ref()),
                    (None, _) => None,
                };
                if let Some(schema) = schema {
                    path.push(key.clone());
                    check_at(schema, &o[key], path, depth + 1)?;
                    path.pop();
                }
            }
        }
        _ => {}
    }

    if let Some(branches) = &c.any_of {
        let mut reasons = Vec::new();
        for branch in branches {
            match check_at(branch, value, &mut path.clone(), depth + 1) {
                Ok(()) => {
                    reasons.clear();
                    break;
                }
                Err(e) => reasons.push(e.to_string()),
            }
        }
        if !reasons.is_empty() {
            return fail(
                path,
                "anyOf",
                format!(
                    "matches none of {} alternatives ({})",
                    branches.len(),
                    reasons.join("; ")
                ),
            );
        }
    }

    Ok(())
}

/// The JSON a [`Value`] is checked as. `None` for values constraints do not
/// speak about (nested resources, Loro documents, translations).
pub fn value_to_json(value: &Value) -> Option<Json> {
    Some(match value {
        Value::AtomicUrl(s) => Json::String(s.to_string()),
        Value::String(s) | Value::Markdown(s) | Value::Slug(s) | Value::Date(s) | Value::Uri(s) => {
            Json::String(s.clone())
        }
        Value::Integer(i) | Value::Timestamp(i) => Json::from(*i),
        Value::Float(f) => Json::Number(serde_json::Number::from_f64(*f)?),
        Value::Boolean(b) => Json::Bool(*b),
        Value::Json(j) => j.clone(),
        Value::ResourceArray(items) => Json::Array(
            items
                .iter()
                .map(|i| match i {
                    SubResource::Subject(s) => Json::String(s.to_string()),
                    SubResource::Nested(_) => Json::Object(Default::default()),
                })
                .collect(),
        ),
        Value::NestedResource(_)
        | Value::LoroDoc(_)
        | Value::LocalizedText(_)
        | Value::Unsupported(_) => return None,
    })
}

/// Checks a [`Value`] against a constraint.
pub fn check_value(c: &Constraint, value: &Value) -> Result<(), ConstraintError> {
    match value_to_json(value) {
        Some(json) => check_json(c, &json),
        None => Ok(()),
    }
}

/// Checks every value of `resource` against the constraints of each class in
/// its `isA`. Classes this store does not have are skipped, and so is a class
/// whose map does not parse (it is rejected when the class is written).
///
/// Error text: `Value for <shortname> breaks <keyword> on class <class>: <detail>`.
pub async fn check_resource(store: &impl Storelike, resource: &Resource) -> AtomicResult<()> {
    let Ok(classes) = resource.get(urls::IS_A).and_then(|v| v.to_subjects(None)) else {
        return Ok(());
    };

    for class_subject in classes {
        let Ok(class) = store.get_resource(&class_subject.as_str().into()).await else {
            continue;
        };
        let constraints = match constraints_of(&class) {
            Ok(Some(c)) => c,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!("Skipping constraints of {class_subject}: {e}");
                continue;
            }
        };

        for (prop, constraint) in &constraints {
            let Some(value) = resource.get(prop).ok().or_else(|| {
                resource
                    .get(&crate::identifiers::to_legacy_scheme(prop))
                    .ok()
            }) else {
                continue;
            };
            if let Err(e) = check_value(constraint, value) {
                let shortname = shortname_of(store, prop).await;
                let class_name = class
                    .get(urls::SHORTNAME)
                    .map(|v| v.to_string())
                    .unwrap_or(class_subject.clone());
                let at = if e.path.is_empty() {
                    String::new()
                } else {
                    format!(" at {}", e.path)
                };
                return Err(format!(
                    "Value for {shortname} breaks {} on class {class_name}{at}: {}",
                    e.keyword, e.detail
                )
                .into());
            }
        }
    }

    Ok(())
}

async fn shortname_of(store: &impl Storelike, prop: &str) -> String {
    if let Ok(res) = store.get_resource(&prop.into()).await {
        if let Ok(s) = res.get(urls::SHORTNAME) {
            return s.to_string();
        }
    }
    prop.to_string()
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    fn to_value(j: &Json) -> Value {
        match j {
            Json::String(s) => Value::String(s.clone()),
            Json::Bool(b) => Value::Boolean(*b),
            Json::Number(n) => match n.as_i64() {
                Some(i) => Value::Integer(i),
                None => Value::Float(n.as_f64().unwrap()),
            },
            Json::Array(a)
                if a.iter()
                    .all(|s| s.as_str().is_some_and(|s| s.contains(':'))) =>
            {
                Value::ResourceArray(
                    a.iter()
                        .map(|s| SubResource::Subject(s.as_str().unwrap().into()))
                        .collect(),
                )
            }
            other => Value::Json(other.clone()),
        }
    }

    #[test]
    fn shared_fixture() {
        let raw = include_str!("../tests/fixtures/class-constraints.json");
        let cases: Vec<Json> = serde_json::from_str(raw).unwrap();
        assert!(cases.len() > 50);

        for case in &cases {
            if case.get("rejected").and_then(Json::as_bool) == Some(true) {
                parse_constraint(&case["constraint"]).unwrap_err();
                continue;
            }
            let constraint = parse_constraint(&case["constraint"]).unwrap();
            let valid = case["valid"].as_bool().unwrap();
            let rule = case.get("rule").and_then(Json::as_str);
            let value = &case["value"];

            // Run both entry points: raw JSON and through a typed `Value`.
            let typed = to_value(value);
            for result in [
                check_json(&constraint, value),
                check_value(&constraint, &typed),
            ] {
                match (&result, valid) {
                    (Ok(()), true) => {}
                    (Err(e), false) => {
                        assert_eq!(Some(e.keyword), rule, "case {case}");
                        if let Some(path) = case.get("path").and_then(Json::as_str) {
                            assert_eq!(e.path, path, "case {case}");
                        }
                    }
                    _ => panic!("case {case} gave {result:?}"),
                }
            }
        }
    }

    #[test]
    fn rejects_bad_maps() {
        for bad in [
            json!({ "p": { "minimun": 1 } }),
            json!({ "p": { "minimum": "1" } }),
            json!({ "p": { "minLength": -1 } }),
            json!({ "p": { "enum": "a" } }),
            json!({ "p": { "pattern": "(" } }),
            json!({ "p": { "class": 1 } }),
            json!({ "p": 1 }),
            json!([]),
        ] {
            parse_constraints(&bad).unwrap_err();
        }
        let ok = parse_constraints(&json!({ "did:ad:prop:x": { "maxItems": 1 } })).unwrap();
        assert!(ok.contains_key("atomic:prop:x"));
    }

    #[tokio::test]
    async fn check_resource_names_property_and_class() {
        let store = crate::Db::init_temp("class_constraints_check")
            .await
            .unwrap();
        store.populate().await.unwrap();

        let mut class = Resource::new_instance(urls::CLASS, &store).await.unwrap();
        class.set_subject("https://example.com/Task".into());
        class
            .set_string(urls::SHORTNAME.into(), "task", &store)
            .await
            .unwrap();
        class
            .set_string(urls::DESCRIPTION.into(), "A task", &store)
            .await
            .unwrap();
        class
            .set_unsafe(
                urls::CONSTRAINTS.into(),
                Value::Json(json!({ urls::NAME: { "maxLength": 3 } })),
            )
            .unwrap();
        validate_constraints_prop(&class).unwrap();
        class.save_locally(&store).await.unwrap();

        let mut task = Resource::new("https://example.com/task1".into());
        task.set_unsafe(
            urls::IS_A.into(),
            Value::ResourceArray(vec![SubResource::Subject(
                "https://example.com/Task".into(),
            )]),
        )
        .unwrap();
        task.set_string(urls::NAME.into(), "abc", &store)
            .await
            .unwrap();
        check_resource(&store, &task).await.unwrap();

        task.set_string(urls::NAME.into(), "abcd", &store)
            .await
            .unwrap();
        let err = check_resource(&store, &task).await.unwrap_err().to_string();
        assert!(
            err.starts_with("Value for name breaks maxLength on class task:"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn check_resource_names_the_nested_path() {
        let store = crate::Db::init_temp("class_constraints_nested")
            .await
            .unwrap();
        store.populate().await.unwrap();
        class_with(
            &store,
            "https://example.com/Patch",
            json!({ urls::NAME: { "type": "object", "properties": {
                "tune": { "type": "number", "minimum": -24, "maximum": 24 } } } }),
        )
        .await;

        let mut patch = Resource::new("https://example.com/patch1".into());
        patch
            .set_unsafe(
                urls::IS_A.into(),
                Value::ResourceArray(vec![SubResource::Subject(
                    "https://example.com/Patch".into(),
                )]),
            )
            .unwrap();
        patch
            .set_unsafe(urls::NAME.into(), Value::Json(json!({ "tune": 24 })))
            .unwrap();
        check_resource(&store, &patch).await.unwrap();

        patch
            .set_unsafe(urls::NAME.into(), Value::Json(json!({ "tune": 25 })))
            .unwrap();
        let err = check_resource(&store, &patch)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.starts_with("Value for name breaks maximum on class thing at /tune:"),
            "{err}"
        );
    }

    async fn class_with(store: &crate::Db, subject: &str, constraints: Json) {
        let mut class = Resource::new_instance(urls::CLASS, store).await.unwrap();
        class.set_subject(subject.into());
        class
            .set_string(urls::SHORTNAME.into(), "thing", store)
            .await
            .unwrap();
        class
            .set_string(urls::DESCRIPTION.into(), "A thing", store)
            .await
            .unwrap();
        class
            .set_unsafe(urls::CONSTRAINTS.into(), Value::Json(constraints))
            .unwrap();
        class.save_locally(store).await.unwrap();
    }

    #[tokio::test]
    async fn effective_constraint_lays_the_class_map_over_the_legacy_property() {
        let store = crate::Db::init_temp("class_constraints_effective")
            .await
            .unwrap();
        store.populate().await.unwrap();

        let prop = "https://example.com/properties/pick";
        let mut property = Resource::new(prop.into());
        property
            .set_unsafe(
                urls::DATATYPE_PROP.into(),
                Value::AtomicUrl(urls::RESOURCE_ARRAY.into()),
            )
            .unwrap();
        property
            .set_unsafe(
                urls::ALLOWS_ONLY.into(),
                Value::ResourceArray(vec![SubResource::Subject(
                    "https://example.com/t/old".into(),
                )]),
            )
            .unwrap();
        property
            .set_unsafe(
                "https://atomicdata.dev/properties/max".into(),
                Value::Integer(5),
            )
            .unwrap();
        property.save_locally(&store).await.unwrap();

        // No class map: the Property's legacy fields speak.
        let none = vec!["https://example.com/NoMap".to_string()];
        let c = effective_constraint(&store, &none, prop).await;
        assert_eq!(
            c.enum_values,
            Some(vec![json!("https://example.com/t/old")])
        );
        assert_eq!(c.max_items, Some(5));

        // A class map wins per keyword; what it leaves unset still falls back.
        class_with(
            &store,
            "https://example.com/A",
            json!({ prop: { "enum": ["https://example.com/t/new"], "maxItems": 1 } }),
        )
        .await;
        class_with(
            &store,
            "https://example.com/B",
            json!({ prop: { "maxItems": 3, "minItems": 1 } }),
        )
        .await;
        let a = vec!["https://example.com/A".to_string()];
        let c = effective_constraint(&store, &a, prop).await;
        assert_eq!(
            c.enum_values,
            Some(vec![json!("https://example.com/t/new")])
        );
        assert_eq!(c.max_items, Some(1));

        // Several classes tighten each other.
        let both = vec![
            "https://example.com/A".to_string(),
            "https://example.com/B".to_string(),
        ];
        let c = effective_constraint(&store, &both, prop).await;
        assert_eq!(c.max_items, Some(1));
        assert_eq!(c.min_items, Some(1));
        assert_eq!(c.to_json()["maxItems"], json!(1));
    }

    #[test]
    fn tightening_keeps_the_stricter_keyword() {
        let a =
            parse_constraint(&json!({ "minimum": 0, "maximum": 10, "enum": [1, 2, 3] })).unwrap();
        let b = parse_constraint(&json!({ "minimum": 2, "maximum": 20, "enum": [3, 2] })).unwrap();
        let t = a.tighten(&b);
        assert_eq!((t.minimum, t.maximum), (Some(2.0), Some(10.0)));
        assert_eq!(t.enum_values, Some(vec![json!(2), json!(3)]));
        assert_eq!(
            parse_constraint(&t.to_json()).unwrap().maximum,
            Some(10.0),
            "to_json is the inverse of parse_constraint"
        );
    }
}
