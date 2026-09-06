//! A value is the part of an Atom that contains the actual information.

use crate::{
    datatype::{match_datatype, DataType},
    errors::AtomicResult,
    resources::PropVals,
    utils::{check_valid_uri, check_valid_url},
    Resource, Subject,
};
use base64::{engine::general_purpose, Engine};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// An individual Value in an Atom.
/// Note that creating values using `Value::from` might result in the wrong Datatype, as the from conversion makes assumptions (e.g. integers are Integers, not Timestamps).
/// Use `Value::SomeDataType()` for explicit creation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Value {
    AtomicUrl(Subject),
    Date(String),
    Integer(i64),
    Float(f64),
    Markdown(String),
    ResourceArray(Vec<SubResource>),
    Slug(String),
    String(String),
    /// Unix Epoch datetime in milliseconds
    Timestamp(i64),
    NestedResource(SubResource),
    Boolean(bool),
    Uri(String),
    Json(serde_json::Value),
    /// Loro CRDT document binary (snapshot or update)
    LoroDoc(Vec<u8>),
    /// Translated strings keyed by BCP 47 language tag (e.g. `nl`, `en-US`).
    /// BTreeMap keeps serialization deterministic (signing).
    LocalizedText(std::collections::BTreeMap<String, String>),
    Unsupported(UnsupportedValue),
}

/// A resource in a Json-AD body can be any of these
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SubResource {
    // I was considering using Resources for these, but that would involve
    // storing the paths in both the NestedResource as well as its parent
    // context, which could produce inconsistencies.
    Nested(PropVals),
    Subject(Subject),
}

/// When the Datatype of a Value is not handled by this library
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnsupportedValue {
    pub value: String,
    /// URL of the datatype
    pub datatype: String,
}

/// Only alphanumeric characters, no spaces
pub const SLUG_REGEX: &str = r"^[a-z0-9]+(?:-[a-z0-9]+)*$";
/// YYYY-MM-DD
pub const DATE_REGEX: &str = r"^\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01])$";
/// Permissive BCP 47 shape check (language, optional subtags). Not a full
/// grammar — it rejects obvious garbage without outlawing rare valid tags.
pub const LANG_TAG_REGEX: &str = r"^[a-zA-Z]{2,8}(-[a-zA-Z0-9]{1,8})*$";

use crate::storelike::Storelike;

impl SubResource {
    pub fn normalize(&mut self, store: &impl Storelike) {
        match self {
            SubResource::Subject(sub) => {
                *sub = store.normalize_subject(sub);
            }
            SubResource::Nested(propvals) => {
                for (_, val) in propvals.iter_mut() {
                    val.normalize(store);
                }
            }
        }
    }
}

impl Value {
    pub fn normalize(&mut self, store: &impl Storelike) {
        match self {
            Value::AtomicUrl(sub) => {
                *sub = store.normalize_subject(sub);
            }
            Value::ResourceArray(sub_arr) => {
                for sub in sub_arr.iter_mut() {
                    sub.normalize(store);
                }
            }
            Value::NestedResource(sub) => {
                sub.normalize(store);
            }
            _ => {}
        }
    }
    /// Check if the value `q_val` is present in `val`
    pub fn contains_value(&self, q_val: &Value) -> bool {
        let query_value = q_val.to_string();
        match self {
            Value::ResourceArray(_vec) => {
                let subs = self.to_subjects(None).unwrap_or_default();
                subs.iter().any(|v| v == &query_value)
            }
            other => other.to_string() == query_value,
        }
    }

    /// Returns the datatype for the value
    pub fn datatype(&self) -> DataType {
        match self {
            Value::AtomicUrl(_) => DataType::AtomicUrl,
            Value::Date(_) => DataType::Date,
            Value::Integer(_) => DataType::Integer,
            Value::Float(_) => DataType::Float,
            Value::Markdown(_) => DataType::Markdown,
            Value::ResourceArray(_) => DataType::ResourceArray,
            Value::Slug(_) => DataType::Slug,
            Value::String(_) => DataType::String,
            Value::Timestamp(_) => DataType::Timestamp,
            // TODO: these datatypes are not the same
            Value::NestedResource(_) => DataType::AtomicUrl,
            Value::Boolean(_) => DataType::Boolean,
            Value::Uri(_) => DataType::Uri,
            Value::Json(_) => DataType::Json,
            Value::LoroDoc(_) => DataType::LoroDoc,
            Value::LocalizedText(_) => DataType::LocalizedText,
            Value::Unsupported(s) => DataType::Unsupported(s.datatype.clone()),
        }
    }

    /// Creates a new Value from an explicit DataType.
    /// Fails if the input string does not convert.
    pub fn new(value: &str, datatype: &DataType) -> AtomicResult<Value> {
        match datatype {
            DataType::Integer => {
                let val: i64 = value.parse()?;
                Ok(Value::Integer(val))
            }
            DataType::Float => {
                let val: f64 = value.parse()?;
                Ok(Value::Float(val))
            }
            DataType::String => Ok(Value::String(value.into())),
            DataType::Markdown => Ok(Value::Markdown(value.into())),
            DataType::Slug => {
                let re = Regex::new(SLUG_REGEX).unwrap();
                if re.is_match(value) {
                    return Ok(Value::Slug(value.into()));
                }
                Err(format!(
                    "Not a valid slug: {}. Only alphanumerics, no spaces allowed.",
                    value
                )
                .into())
            }
            DataType::AtomicUrl => {
                check_valid_url(value)?;
                Ok(Value::AtomicUrl(value.into()))
            }
            DataType::Uri => {
                check_valid_uri(value)?;
                Ok(Value::Uri(value.into()))
            }
            DataType::Json => {
                let json: serde_json::Value = serde_json::from_str(value)?;
                Ok(Value::Json(json))
            }
            DataType::ResourceArray => {
                let vector: Vec<String> = crate::parse::parse_json_array(value).map_err(|e| {
                    format!("Could not deserialize ResourceArray: {}. Should be a Json array of strings. {}", &value, e)
                })?;
                let mut new_vec = Vec::new();
                for i in vector {
                    new_vec.push(SubResource::Subject(i.into()));
                }
                Ok(Value::ResourceArray(new_vec))
            }
            DataType::Date => {
                let re = Regex::new(DATE_REGEX).unwrap();
                if re.is_match(value) {
                    return Ok(Value::Date(value.into()));
                }
                Err(format!("Not a valid date: {}. Needs to be YYYY-MM-DD.", value).into())
            }
            DataType::Timestamp => {
                let val: i64 = value
                    .parse()
                    .map_err(|e| format!("Not a valid Timestamp: {}. {}", value, e))?;
                Ok(Value::Timestamp(val))
            }
            DataType::Unsupported(unsup_url) => Ok(Value::Unsupported(UnsupportedValue {
                value: value.into(),
                datatype: unsup_url.into(),
            })),
            DataType::Boolean => {
                let bool = match value {
                    "true" => true,
                    "false" => false,
                    other => {
                        return Err(format!(
                            "Not a valid boolean value: {}, should be 'true' or 'false'.",
                            other
                        )
                        .into())
                    }
                };
                Ok(Value::Boolean(bool))
            }
            DataType::LoroDoc => {
                let bin = general_purpose::STANDARD
                    .decode(value)
                    .map_err(|e| format!("Not a valid Base64 string: {}. {}", value, e))?;
                Ok(Value::LoroDoc(bin))
            }
            DataType::LocalizedText => {
                let json: serde_json::Value = serde_json::from_str(value)?;
                Value::localized_text_from_json(&json)
            }
        }
    }

    /// Builds a `Value::LocalizedText` from a JSON object of
    /// `{ "<BCP 47 tag>": "<translated string>" }`.
    pub fn localized_text_from_json(json: &serde_json::Value) -> AtomicResult<Value> {
        let serde_json::Value::Object(obj) = json else {
            return Err(format!(
                "Not a valid LocalizedText: {}. Should be a JSON object of language tag -> string.",
                json
            )
            .into());
        };
        let re = Regex::new(LANG_TAG_REGEX).unwrap();
        let mut map = std::collections::BTreeMap::new();
        for (tag, val) in obj {
            if !re.is_match(tag) {
                return Err(format!(
                    "Not a valid language tag in LocalizedText: {}. Use BCP 47 tags like 'en' or 'nl-BE'.",
                    tag
                )
                .into());
            }
            let serde_json::Value::String(s) = val else {
                return Err(format!(
                    "Not a valid LocalizedText value for tag {}: {}. Should be a string.",
                    tag, val
                )
                .into());
            };
            map.insert(tag.clone(), s.clone());
        }
        Ok(Value::LocalizedText(map))
    }

    /// Returns a new Value, accepts a datatype string
    pub fn new_from_string(value: &str, datatype: &str) -> AtomicResult<Value> {
        Value::new(value, &match_datatype(datatype))
    }

    /// Turns the value into a Vector of subject strings.
    /// Works for resource arrays with nested resources, full resources, single resources.
    /// Returns a path for for Anonymous Nested Resources, which is why you need to pass a parent_path e.g. `http://example.com/foo/bar https://atomicdata.dev/properties/children`.
    pub fn to_subjects(&self, parent_path: Option<String>) -> AtomicResult<Vec<String>> {
        let mut vec: Vec<String> = Vec::new();
        match self {
            Value::ResourceArray(arr) => {
                arr.iter()
                    .enumerate()
                    .for_each(|(i, r)| match r.to_owned() {
                        SubResource::Nested(_e) => {
                            let path_base = if let Some(p) = &parent_path {
                                p.to_string()
                            } else {
                                "nested_resource_without_parent_path".into()
                            };
                            vec.push(format!("{} {}", path_base, i))
                        }
                        SubResource::Subject(s) => vec.push(s.to_string()),
                    });
                Ok(vec)
            }
            Value::AtomicUrl(s) => {
                vec.push(s.to_string());
                Ok(vec)
            }
            Value::NestedResource(_nr) => {
                // TODO: change the data model of nested resources to store the subject of the parent, so we can construct a path
                Err("Can't convert nested resources to subjects.".into())
            }
            other => Err(format!("Value {} is not a Resource Array, but {}", self, other).into()),
        }
    }

    pub fn to_bool(&self) -> AtomicResult<bool> {
        if let Value::Boolean(bool) = self {
            return Ok(bool.to_owned());
        }
        Err(format!("Value {} is not a Boolean", self).into())
    }

    /// Returns an Integer, if the Atom is one.
    pub fn to_int(&self) -> AtomicResult<i64> {
        match self {
            Value::Timestamp(int) | Value::Integer(int) => Ok(int.to_owned()),
            _ => self.to_string().parse::<i64>().map_err(|e| {
                format!("Value {} cannot be converted into integer. {}", self, e).into()
            }),
        }
    }

    /// Returns a PropVals Hashmap, if the Atom is a NestedResource
    pub fn to_nested(&self) -> AtomicResult<&PropVals> {
        if let Value::NestedResource(SubResource::Nested(nested)) = self {
            return Ok(nested);
        }
        Err(format!("Value {} is not a Nested Resource", self).into())
    }

    /// Returns a Lexicographically sortable string representation of the value
    pub fn to_sortable_string(&self) -> SortableValue {
        match self {
            Value::ResourceArray(arr) => arr.len().to_string(),
            // Sort by one language so ordering is stable across resources:
            // `en` when present, else the first tag. The query index cannot
            // know the requester's language.
            Value::LocalizedText(map) => map
                .get("en")
                .or_else(|| map.values().next())
                .cloned()
                .unwrap_or_default(),
            other => other.to_string(),
        }
    }

    /// Picks the best translation for a preferred language: exact tag →
    /// primary subtag (`en-US` → `en`) → `en` → the first tag. Returns None
    /// only when the map is empty.
    pub fn to_localized_string(&self, preferred: &str) -> Option<&str> {
        let Value::LocalizedText(map) = self else {
            return None;
        };
        if let Some(s) = map.get(preferred) {
            return Some(s);
        }
        let primary = preferred.split('-').next().unwrap_or(preferred);
        map.get(primary)
            .or_else(|| map.get("en"))
            .or_else(|| map.values().next())
            .map(|s| s.as_str())
    }

    /// Converts one Value to a bunch of indexable items.
    /// Returns None for unsupported types.
    pub fn to_reference_index_strings(&self) -> Option<Vec<ReferenceString>> {
        let vals = match self {
            // TODO: This results in wrong indexing, as some subjects will be numbers.
            Value::ResourceArray(_v) => self.to_subjects(None).unwrap_or_else(|_| vec![]),
            Value::AtomicUrl(v) => vec![v.to_string()],
            Value::NestedResource(_) | Value::LoroDoc(_) => return None,
            // This might result in unnecessarily long strings, sometimes. We may want to shorten them later.
            val => vec![val.to_string()],
        };
        Some(vals)
    }
}

/// A value that is meant for checking reference indexes.
/// short. Vectors of subjects are turned into individual ReferenceStrings.
pub type ReferenceString = String;

/// String Value representing a lexicographically sortable string.
pub type SortableValue = String;

impl From<String> for Value {
    fn from(val: String) -> Self {
        Value::String(val)
    }
}

impl From<i32> for Value {
    fn from(val: i32) -> Self {
        Value::Integer(val as i64)
    }
}

impl From<usize> for Value {
    fn from(val: usize) -> Self {
        Value::Integer(val as i64)
    }
}

impl From<Vec<&str>> for Value {
    fn from(val: Vec<&str>) -> Self {
        let mut vec = Vec::new();
        for i in val {
            vec.push(SubResource::Subject(i.into()));
        }
        Value::ResourceArray(vec)
    }
}

impl From<Vec<String>> for Value {
    fn from(val: Vec<String>) -> Self {
        let mut vec = Vec::new();
        for i in val {
            vec.push(SubResource::Subject(i.into()));
        }
        Value::ResourceArray(vec)
    }
}

impl From<Vec<Subject>> for Value {
    fn from(val: Vec<Subject>) -> Self {
        let mut vec = Vec::new();
        for subject in val {
            vec.push(SubResource::Subject(subject));
        }
        Value::ResourceArray(vec)
    }
}

impl From<Vec<SubResource>> for Value {
    fn from(val: Vec<SubResource>) -> Self {
        Value::ResourceArray(val)
    }
}

impl From<SubResource> for Value {
    fn from(val: SubResource) -> Self {
        match val {
            SubResource::Nested(n) => n.into(),
            SubResource::Subject(s) => Value::AtomicUrl(s),
        }
    }
}

impl From<PropVals> for Value {
    fn from(val: PropVals) -> Self {
        Value::NestedResource(SubResource::Nested(val))
    }
}

impl From<bool> for Value {
    fn from(val: bool) -> Self {
        Value::Boolean(val)
    }
}

impl From<f64> for Value {
    fn from(val: f64) -> Self {
        Value::Float(val)
    }
}

use std::fmt;
impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::AtomicUrl(s) => write!(f, "{}", s),
            Value::Date(s) => write!(f, "{}", s),
            Value::Integer(i) => write!(f, "{}", i),
            Value::Float(float) => write!(f, "{}", float),
            Value::Markdown(i) => write!(f, "{}", i),
            Value::ResourceArray(v) => {
                let out = v
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<String>>()
                    .join(",");
                write!(f, "{}", out)
            }
            Value::Slug(s) => write!(f, "{}", s),
            Value::String(s) => write!(f, "{}", s),
            Value::Timestamp(i) => write!(f, "{}", i),
            Value::NestedResource(n) => write!(f, "{:?}", n),
            Value::Boolean(b) => write!(f, "{}", b),
            Value::Uri(s) => write!(f, "{}", s),
            Value::Json(s) => write!(f, "{}", s),
            Value::LoroDoc(s) => write!(f, "{}", general_purpose::STANDARD.encode(s)),
            Value::LocalizedText(map) => {
                // BTreeMap serializes with sorted keys → deterministic bytes.
                let json = serde_json::to_string(map).map_err(|_| fmt::Error)?;
                write!(f, "{}", json)
            }
            Value::Unsupported(u) => write!(f, "{}", u.value),
        }
    }
}

impl fmt::Display for SubResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s: String = String::new();

        match self {
            SubResource::Nested(pv) => {
                let serialized =
                    crate::serialize::propvals_to_json_ad_map(pv, None, "http://localhost/", true)
                        .unwrap_or_else(|_e| {
                            serde_json::Value::String(format!(
                                "Could not serialize {:?} : {}",
                                pv, _e
                            ))
                        });
                s.push_str(&serialized.to_string());
            }
            SubResource::Subject(sub) => s.push_str(sub.as_str()),
        }
        write!(f, "{}", s)
    }
}

impl From<&str> for SubResource {
    fn from(val: &str) -> Self {
        SubResource::Subject(val.into())
    }
}

impl From<String> for SubResource {
    fn from(val: String) -> Self {
        SubResource::Subject(val.into())
    }
}

impl From<PropVals> for SubResource {
    fn from(val: PropVals) -> Self {
        SubResource::Nested(val)
    }
}

impl From<Resource> for SubResource {
    fn from(val: Resource) -> Self {
        SubResource::Subject(val.get_subject().clone())
    }
}

impl From<crate::Subject> for SubResource {
    fn from(val: crate::Subject) -> Self {
        SubResource::Subject(val)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn formats_correct_value() {
        let int = Value::new("8", &DataType::Integer).unwrap();
        assert!(int.to_string() == "8");
        let string = Value::new("string", &DataType::String).unwrap();
        assert!(string.to_string() == "string");
        let date = Value::new("1200-02-02", &DataType::Date).unwrap();
        assert!(date.to_string() == "1200-02-02");
        let float = Value::new("1.123123", &DataType::Float).unwrap();
        assert!(float.to_string() == "1.123123");
        let uri = Value::new("ldap://[2001:db8::7]/c=GB?objectClass?one", &DataType::Uri).unwrap();
        assert!(uri.to_string() == "ldap://[2001:db8::7]/c=GB?objectClass?one");

        let json = Value::new("{\"foo\": \"bar\", \"baz\": 123}", &DataType::Json).unwrap();
        // Note: Json serialization switches the order of the keys.
        assert!(
            json.to_string() == "{\"baz\":123,\"foo\":\"bar\"}"
                || json.to_string() == "{\"foo\":\"bar\",\"baz\":123}"
        );

        let converted = Value::from(8);
        assert!(converted.to_string() == "8");
    }

    #[test]
    fn fails_wrong_values() {
        Value::new("no int", &DataType::Integer).unwrap_err();
        Value::new("1.1", &DataType::Integer).unwrap_err();
        Value::new("no spaces", &DataType::Slug).unwrap_err();
        Value::new("120-02-02", &DataType::Date).unwrap_err();
        Value::new("12000-02-02", &DataType::Date).unwrap_err();
        Value::new("a", &DataType::Float).unwrap_err();
        Value::new("blabliebla", &DataType::Uri).unwrap_err();
        Value::new(
            "{\"foo\": \"bar\", \"trailing comma\": 123,}",
            &DataType::Json,
        )
        .unwrap_err();
    }

    #[test]
    fn value_conversions_from_and_datatypes() {
        let int = Value::from(8);
        assert_eq!(int.datatype(), DataType::Integer);
        assert_eq!(int.to_string(), "8");
        let resource_rray = Value::from(vec!["https://atomicdata.dev/properties/description"]);
        assert_eq!(resource_rray.datatype(), DataType::ResourceArray);
        assert_eq!(
            resource_rray.to_string(),
            "https://atomicdata.dev/properties/description"
        );
        let float = Value::from(1.123123);
        assert_eq!(float.datatype(), DataType::Float);
        assert_eq!(float.to_string(), "1.123123");
        let converted = Value::from(8);
        assert_eq!(converted.datatype(), DataType::Integer);
        assert_eq!(converted.to_string(), "8");
    }

    #[test]
    fn localized_text_parses_validates_and_resolves() {
        let val = Value::new(
            r#"{"en": "Fast sync", "nl": "Snelle synchronisatie", "en-US": "Fast sync (US)"}"#,
            &DataType::LocalizedText,
        )
        .unwrap();
        assert_eq!(val.datatype(), DataType::LocalizedText);
        // Display is deterministic (sorted keys) and re-parses.
        let reparsed = Value::new(&val.to_string(), &DataType::LocalizedText).unwrap();
        assert_eq!(reparsed.to_string(), val.to_string());
        // Fallback chain: exact → primary subtag → en → first.
        assert_eq!(val.to_localized_string("en-US"), Some("Fast sync (US)"));
        assert_eq!(
            val.to_localized_string("nl-BE"),
            Some("Snelle synchronisatie")
        );
        assert_eq!(val.to_localized_string("de"), Some("Fast sync"));
        assert_eq!(val.to_sortable_string(), "Fast sync");

        // Invalid shapes are rejected.
        Value::new("\"just a string\"", &DataType::LocalizedText).unwrap_err();
        Value::new(r#"{"not a tag!": "x"}"#, &DataType::LocalizedText).unwrap_err();
        Value::new(r#"{"en": 5}"#, &DataType::LocalizedText).unwrap_err();
    }

    #[test]
    fn loro_doc_is_not_indexed() {
        let blob = vec![0u8; 2048];
        let atom = crate::Atom::new(
            "did:ad:commit:test".into(),
            crate::urls::LORO_UPDATE.into(),
            Value::LoroDoc(blob),
        );
        assert!(
            atom.to_indexable_atoms().is_empty(),
            "Loro binary payloads must not become KV index keys"
        );
        assert!(Value::LoroDoc(vec![1, 2, 3])
            .to_reference_index_strings()
            .is_none());
    }

    #[test]
    fn value_to_subjects() {
        let subject_string = String::from("https://example.com/subject_string");
        let mut nested = PropVals::new();
        nested.insert(
            crate::urls::DESCRIPTION.into(),
            Value::Markdown("test".into()),
        );
        let full_resource = Resource::new("https://example.com/full_resource".into());
        let array_no_nested = Value::ResourceArray(vec![
            subject_string.clone().into(),
            full_resource.clone().into(),
        ]);
        assert_eq!(array_no_nested.to_subjects(None).unwrap().len(), 2);
        let array_nested = Value::ResourceArray(vec![
            subject_string.into(),
            full_resource.clone().into(),
            nested.into(),
        ]);
        let atom = crate::Atom::new(
            "https://example.com/parent_resource".into(),
            crate::urls::PARENT.into(),
            array_nested,
        );
        assert_eq!(
            atom.values_to_subjects().unwrap(),
            vec![
                "https://example.com/subject_string".to_string(),
                full_resource.get_subject().to_string(),
                "https://example.com/parent_resource https://atomicdata.dev/properties/parent 2"
                    .into(),
            ]
        );
    }
}
