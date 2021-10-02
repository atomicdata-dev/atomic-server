//! A value is the part of an Atom that contains the actual information.

use crate::{
    datatype::match_datatype, datatype::DataType, errors::AtomicResult, resources::PropVals,
    url_helpers::check_valid_url, Resource,
};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// An individual Value in an Atom, represented as a native Rust enum.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Value {
    AtomicUrl(String),
    Date(String),
    Integer(i64),
    Float(f64),
    Markdown(String),
    ResourceArraySubjects(Vec<String>),
    ResourceArrayNested(Vec<Resource>),
    Slug(String),
    String(String),
    /// Unix Epoch datetime in milliseconds
    Timestamp(i64),
    NestedResource(PropVals),
    Resource(Resource),
    Boolean(bool),
    Unsupported(UnsupportedValue),
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
            Value::ResourceArraySubjects(_) => DataType::ResourceArray,
            Value::ResourceArrayNested(_) => DataType::ResourceArray,
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
                let vector: Vec<String> = crate::parse::parse_json_array(&value).map_err(|e| {
                    return format!("Could not deserialize ResourceArray: {}. Should be a JSON array of strings. {}", &value, e);
                })?;
                Ok(Value::ResourceArraySubjects(vector))
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

    /// Returns a Vector, if the Value is one
    pub fn to_vec(&self) -> AtomicResult<&Vec<String>> {
        if let Value::ResourceArraySubjects(arr) = self {
            return Ok(arr);
        }
        Err(format!("Value {} is not a Resource Array", self).into())
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
        if let Value::NestedResource(nested) = self {
            return Ok(nested);
        }
        Err(format!("Value {} is not a Nested Resource", self).into())
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

// impl From<u64> for Value {
//     fn from(val: u64) -> Self {
//         // This might panic. Perhaps this is not a good idea
//         Value::Integer(val as i64)
//     }
// }

impl From<usize> for Value {
    fn from(val: usize) -> Self {
        Value::Integer(val as i64)
    }
}

impl From<Vec<String>> for Value {
    fn from(val: Vec<String>) -> Self {
        Value::ResourceArraySubjects(val)
    }
}

impl From<PropVals> for Value {
    fn from(val: PropVals) -> Self {
        Value::NestedResource(val)
    }
}

impl From<bool> for Value {
    fn from(val: bool) -> Self {
        Value::Boolean(val)
    }
}

impl From<Resource> for Value {
    fn from(val: Resource) -> Self {
        Value::Resource(val)
    }
}

impl From<Vec<Resource>> for Value {
    fn from(val: Vec<Resource>) -> Self {
        Value::ResourceArrayNested(val)
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
            Value::ResourceArraySubjects(v) => {
                let s = crate::serialize::serialize_json_array(v)
                    .unwrap_or_else(|_e| format!("Could not serialize resource array: {:?}", v));
                write!(f, "{}", s)
            }
            Value::ResourceArrayNested(v) => {
                let s = crate::serialize::resources_to_json_ad(v).unwrap_or_else(|_e| {
                    format!("Could not serialize nested resource array: {:?}", v)
                });
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
        let date = Value::new("1.123123", &DataType::Float).unwrap();
        assert!(date.to_string() == "1.123123");
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
}
