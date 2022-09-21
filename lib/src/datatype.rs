//! [DataType]s constrain values of Atoms

use crate::urls;
use serde::{Deserialize, Serialize};
use std::{fmt, string::ParseError};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DataType {
    /// Either a full Resource, a link to a resource (subject) or a Nested Anonymous Resource
    AtomicUrl,
    Boolean,
    Date,
    Integer,
    Float,
    Markdown,
    ResourceArray,
    Slug,
    String,
    Timestamp,
    Unsupported(String),
}

pub fn match_datatype(string: &str) -> DataType {
    match string {
        urls::ATOMIC_URL => DataType::AtomicUrl,
        urls::BOOLEAN => DataType::Boolean,
        urls::DATE => DataType::Date,
        urls::INTEGER => DataType::Integer,
        urls::FLOAT => DataType::Float,
        urls::MARKDOWN => DataType::Markdown,
        urls::RESOURCE_ARRAY => DataType::ResourceArray,
        urls::SLUG => DataType::Slug,
        urls::STRING => DataType::String,
        urls::TIMESTAMP => DataType::Timestamp,
        unsupported_datatype => DataType::Unsupported(unsupported_datatype.into()),
    }
}

impl std::str::FromStr for DataType {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            urls::ATOMIC_URL => DataType::AtomicUrl,
            urls::BOOLEAN => DataType::Boolean,
            urls::DATE => DataType::Date,
            urls::INTEGER => DataType::Integer,
            urls::FLOAT => DataType::Float,
            urls::MARKDOWN => DataType::Markdown,
            urls::RESOURCE_ARRAY => DataType::ResourceArray,
            urls::SLUG => DataType::Slug,
            urls::STRING => DataType::String,
            urls::TIMESTAMP => DataType::Timestamp,
            unsupported_datatype => DataType::Unsupported(unsupported_datatype.into()),
        })
    }
}

impl fmt::Display for DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataType::AtomicUrl => write!(f, "{}", urls::ATOMIC_URL),
            DataType::Boolean => write!(f, "{}", urls::BOOLEAN),
            DataType::Date => write!(f, "{}", urls::DATE),
            DataType::Integer => write!(f, "{}", urls::INTEGER),
            DataType::Float => write!(f, "{}", urls::FLOAT),
            DataType::Markdown => write!(f, "{}", urls::MARKDOWN),
            DataType::ResourceArray => write!(f, "{}", urls::RESOURCE_ARRAY),
            DataType::Slug => write!(f, "{}", urls::SLUG),
            DataType::String => write!(f, "{}", urls::STRING),
            DataType::Timestamp => write!(f, "{}", urls::TIMESTAMP),
            DataType::Unsupported(url) => write!(f, "{}", url),
        }
    }
}
