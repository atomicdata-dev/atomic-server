//! A value is the part of an Atom that contains the actual information.

use crate::{
    datatype::match_datatype, datatype::DataType, errors::AtomicResult, resources::PropVals,
    utils::check_valid_url, Resource,
};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// An individual Value in an Atom.
/// Note that creating values using `Value::from` might result in the wrong Datatype, as the from conversion makes assumptions (e.g. integers are Integers, not Timestamps).
/// Use `Value::SomeDataType()` for explicit creation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Value {
    AtomicUrl(String),
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
    Resource(Resource),
    Boolean(bool),
    Unsupported(UnsupportedValue),
}

/// A resource in a JSON-AD body can be any of these
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SubResource {
    Resource(Box<Resource>),
    // I was considering using Resources for these, but that would involve
    // storing the paths in both the NestedResource as well as its parent
    // context, which could produce inconsistencies.
    Nested(PropVals),
    Subject(String),
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

impl Value {
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
            Value::Resource(_) => DataType::AtomicUrl,
            Value::Boolean(_) => DataType::Boolean,
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
                if re.is_match(&*value) {
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
            DataType::ResourceArray => {
                let vector: Vec<String> = crate::parse::parse_json_array(value).map_err(|e| {
                    return format!("Could not deserialize ResourceArray: {}. Should be a JSON array of strings. {}", &value, e);
                })?;
                let mut new_vec = Vec::new();
                for i in vector {
                    new_vec.push(SubResource::Subject(i));
                }
                Ok(Value::ResourceArray(new_vec))
            }
            DataType::Date => {
                let re = Regex::new(DATE_REGEX).unwrap();
                if re.is_match(&*value) {
                    return Ok(Value::Date(value.into()));
                }
                Err(format!("Not a valid date: {}. Needs to be YYYY-MM-DD.", value).into())
            }
            DataType::Timestamp => {
                let val: i64 = value
                    .parse()
                    .map_err(|e| return format!("Not a valid Timestamp: {}. {}", value, e))?;
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
        }
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
                        SubResource::Resource(e) => vec.push(e.get_subject().into()),
                        SubResource::Nested(_e) => {
                            let path_base = if let Some(p) = &parent_path {
                                p.to_string()
                            } else {
                                "nested_resource_without_parent_path".into()
                            };
                            vec.push(format!("{} {}", path_base, i))
                        }
                        SubResource::Subject(s) => vec.push(s),
                    });
                Ok(vec)
            }
            Value::AtomicUrl(s) => {
                vec.push(s.into());
                Ok(vec)
            }
            Value::NestedResource(_nr) => {
                // TODO: change the data model of nested resources to store the subject of the parent, so we can construct a path
                Err("Can't convert nested resources to subjects.".into())
            }
            Value::Resource(r) => {
                vec.push(r.get_subject().into());
                Ok(vec)
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
    pub fn to_sortable_string(&self) -> String {
        match self {
            Value::ResourceArray(arr) => arr.len().to_string(),
            other => other.to_string(),
        }
    }
}

/// Check if the value `q_val` is present in `val`
pub fn query_value_compare(val: &Value, q_val: &Value) -> bool {
    let query_value = q_val.to_string();
    match val {
        Value::ResourceArray(_vec) => {
            let subs = val.to_subjects(None).unwrap_or_default();
            subs.iter().any(|v| v == &query_value)
        }
        other => other.to_string() == query_value,
    }
}

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
            vec.push(SubResource::Subject(i));
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
            SubResource::Resource(r) => r.into(),
            SubResource::Nested(n) => n.into(),
            SubResource::Subject(s) => s.into(),
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

impl From<Resource> for Value {
    fn from(val: Resource) -> Self {
        Value::Resource(val)
    }
}

impl From<Box<Resource>> for Value {
    fn from(val: Box<Resource>) -> Self {
        Value::Resource((*val).into())
    }
}

impl From<Vec<Resource>> for Value {
    fn from(val: Vec<Resource>) -> Self {
        let mut vec = Vec::new();
        for i in val {
            vec.push(SubResource::Resource(Box::new(i)));
        }
        Value::ResourceArray(vec)
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
                let mut s: String = String::new();
                for i in v {
                    s.push_str(&i.to_string());
                }
                write!(f, "{}", s)
            }
            Value::Slug(s) => write!(f, "{}", s),
            Value::String(s) => write!(f, "{}", s),
            Value::Timestamp(i) => write!(f, "{}", i),
            Value::Resource(r) => write!(
                f,
                "{}",
                r.to_json_ad()
                    .unwrap_or_else(|_e| format!("Could not serialize resource: {:?}", r))
            ),
            Value::NestedResource(n) => write!(f, "{:?}", n),
            Value::Boolean(b) => write!(f, "{}", b),
            Value::Unsupported(u) => write!(f, "{}", u.value),
        }
    }
}

impl fmt::Display for SubResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s: String = String::new();

        match self {
            SubResource::Resource(r) => {
                s.push_str(
                    &r.to_json_ad()
                        .unwrap_or_else(|_e| format!("Could not serialize resource: {:?}", r)),
                );
            }
            SubResource::Nested(pv) => {
                let serialized = crate::serialize::propvals_to_json_ad_map(pv, None)
                    .unwrap_or_else(|_e| {
                        return serde_json::Value::String(format!(
                            "Could not serialize {:?} : {}",
                            pv, _e
                        ));
                    });
                s.push_str(&serialized.to_string());
            }
            SubResource::Subject(sub) => s.push_str(sub),
        }
        write!(f, "{}", s)
    }
}

impl From<&str> for SubResource {
    fn from(val: &str) -> Self {
        SubResource::Subject(val.to_owned())
    }
}

impl From<String> for SubResource {
    fn from(val: String) -> Self {
        SubResource::Subject(val)
    }
}

impl From<PropVals> for SubResource {
    fn from(val: PropVals) -> Self {
        SubResource::Nested(val)
    }
}

impl From<Resource> for SubResource {
    fn from(val: Resource) -> Self {
        SubResource::Resource(Box::new(val))
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
                full_resource.get_subject().into(),
                "https://example.com/parent_resource https://atomicdata.dev/properties/parent 2"
                    .into(),
            ]
        );
    }
}
