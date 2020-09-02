use crate::errors::AtomicResult;
use crate::serialize;
use crate::urls;
use regex::Regex;
use serde::{Serialize, Deserialize};

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

#[derive(Clone, Debug, Serialize)]
pub enum DataType {
    AtomicUrl,
    Date,
    Integer,
    Markdown,
    ResourceArray,
    Slug,
    String,
    Timestamp,
    Unsupported(String),
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
    pub fn new(value: &String, datatype: &DataType) -> AtomicResult<Value> {
        match datatype {
            DataType::Integer => {
                let val: i32 = value.parse()?;
                return Ok(Value::Integer(val));
            }
            DataType::String => return Ok(Value::String(value.clone())),
            DataType::Markdown => return Ok(Value::Markdown(value.clone())),
            DataType::Slug => {
                let re = Regex::new(SLUG_REGEX).unwrap();
                if re.is_match(&*value) {
                    return Ok(Value::Slug(value.clone()));
                }
                return Err(format!("Not a valid slug: {}", value).into());
            }
            DataType::AtomicUrl => return Ok(Value::AtomicUrl(value.clone())),
            DataType::ResourceArray => {
                let vector: Vec<String> = serialize::deserialize_json_array(&value)
                    .map_err(|e| return format!("Could not deserialize ResourceArray: {}. {}", &value, e))?;
                return Ok(Value::ResourceArray(vector));
            }
            DataType::Date => {
                let re = Regex::new(DATE_REGEX).unwrap();
                if re.is_match(&*value) {
                    return Ok(Value::Date(value.clone()));
                }
                return Err(format!("Not a valid date: {}", value).into());
            }
            DataType::Timestamp => {
                let val: i64 = value.parse().map_err(|e| return format!("Not a valid Timestamp: {}. {}", value, e ))?;
                return Ok(Value::Timestamp(val));
            }
            DataType::Unsupported(unsup_url) => {
                return Ok(Value::Unsupported(UnsupportedValue {
                    value: value.into(),
                    datatype: unsup_url.into(),
                }))
            }
        };
    }

    pub fn to_string(&self) -> String {
      match self {
          Value::AtomicUrl(s) => s.clone(),
          Value::Date(s) => s.clone(),
          Value::Integer(i) => i.to_string(),
          Value::Markdown(i) => i.clone(),
          Value::ResourceArray(v) => serialize::serialize_json_array(v).expect("Could not serialize resource array"),
          Value::Slug(s) => s.clone(),
          Value::String(s) => s.clone(),
          Value::Timestamp(i) => i.to_string(),
          Value::Unsupported(u) => u.value.clone(),
      }
    }

    /// Returns a new Value, accepts a datatype string
    pub fn new_from_string(value: &String, datatype: &String) -> AtomicResult<Value> {
      Value::new(value, &match_datatype(datatype))
    }
}

pub fn match_datatype(string: &String) -> DataType {
  match string.as_str() {
      urls::INTEGER => DataType::Integer,
      urls::STRING => DataType::String,
      urls::MARKDOWN => DataType::Markdown,
      urls::SLUG => DataType::Slug,
      urls::ATOMIC_URL => DataType::AtomicUrl,
      urls::RESOURCE_ARRAY => DataType::ResourceArray,
      urls::DATE => DataType::Date,
      urls::TIMESTAMP => DataType::Timestamp,
      unsupported_datatype => return DataType::Unsupported(unsupported_datatype.into()),
  }
}
impl From<String> for Value {
    fn from(string: String) -> Self {
        Value::new(&string, &DataType::String).unwrap()
    }
}
