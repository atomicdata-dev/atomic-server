//! A value is the part of an Atom that contains the actual information.

use crate::{errors::AtomicResult, datatype::DataType, datatype::match_datatype};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// An individual Value in an Atom, represented as a native Rust enum.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Value {
    AtomicUrl(String),
    Date(String),
    Integer(i32),
    Markdown(String),
    ResourceArray(Vec<String>),
    Slug(String),
    String(String),
    Timestamp(i64),
    Unsupported(UnsupportedValue),
}

/// When the Datatype of a Value is not handled by this library
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnsupportedValue {
    pub value: String,
    /// URL of the datatype
    pub datatype: String,
}

pub const SLUG_REGEX: &str = r"^[a-z0-9]+(?:-[a-z0-9]+)*$";
pub const DATE_REGEX: &str = r"^\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01])$";

impl Value {
    pub fn new(value: &str, datatype: &DataType) -> AtomicResult<Value> {
        match datatype {
            DataType::Integer => {
                let val: i32 = value.parse()?;
                Ok(Value::Integer(val))
            }
            DataType::String => Ok(Value::String(value.into())),
            DataType::Markdown => Ok(Value::Markdown(value.into())),
            DataType::Slug => {
                let re = Regex::new(SLUG_REGEX).unwrap();
                if re.is_match(&*value) {
                    return Ok(Value::Slug(value.into()));
                }
                Err(format!("Not a valid slug: {}", value).into())
            }
            DataType::AtomicUrl => Ok(Value::AtomicUrl(value.into())),
            DataType::ResourceArray => {
                let vector: Vec<String> = crate::parse::parse_json_array(&value).map_err(|e| {
                    return format!("Could not deserialize ResourceArray: {}. {}", &value, e);
                })?;
                Ok(Value::ResourceArray(vector))
            }
            DataType::Date => {
                let re = Regex::new(DATE_REGEX).unwrap();
                if re.is_match(&*value) {
                    return Ok(Value::Date(value.into()));
                }
                Err(format!("Not a valid date: {}", value).into())
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
        }
    }

    /// Returns a new Value, accepts a datatype string
    pub fn new_from_string(value: &str, datatype: &str) -> AtomicResult<Value> {
        Value::new(value, &match_datatype(datatype))
    }
}

impl From<String> for Value {
    fn from(val: String) -> Self {
        Value::String(val)
    }
}

impl From<i32> for Value {
    fn from(val: i32) -> Self {
        Value::Integer(val)
    }
}

impl From<Vec<String>> for Value {
    fn from(val: Vec<String>) -> Self {
        Value::ResourceArray(val)
    }
}

use std::fmt;
impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::AtomicUrl(s) => write!(f, "{}", s),
            Value::Date(s) => write!(f, "{}", s),
            Value::Integer(i) => write!(f, "{}", i),
            Value::Markdown(i) => write!(f, "{}", i),
            Value::ResourceArray(v) => {
                let s = crate::serialize::serialize_json_array_owned(v)
                    .unwrap_or_else(|_e| format!("[Could not serialize resource array: {:?}", v));
                write!(f, "{}", s)
            }
            Value::Slug(s) => write!(f, "{}", s),
            Value::String(s) => write!(f, "{}", s),
            Value::Timestamp(i) => write!(f, "{}", i),
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

        let converted  = Value::from(8);
        assert!(converted.to_string() == "8");
    }

    #[test]
    fn fails_wrong_values() {
        Value::new("no int", &DataType::Integer).unwrap_err();
        Value::new("no spaces", &DataType::Slug).unwrap_err();
        Value::new("120-02-02", &DataType::Date).unwrap_err();
        Value::new("12000-02-02", &DataType::Date).unwrap_err();
    }
}
