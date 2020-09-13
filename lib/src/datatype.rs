//! Datatypes constrain values of Atoms

use std::fmt;
use serde::{Deserialize, Serialize};
use crate::urls;

#[derive(Clone, Debug, Serialize, Deserialize)]
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

pub fn match_datatype(string: &str) -> DataType {
    match string {
        urls::INTEGER => DataType::Integer,
        urls::STRING => DataType::String,
        urls::MARKDOWN => DataType::Markdown,
        urls::SLUG => DataType::Slug,
        urls::ATOMIC_URL => DataType::AtomicUrl,
        urls::RESOURCE_ARRAY => DataType::ResourceArray,
        urls::DATE => DataType::Date,
        urls::TIMESTAMP => DataType::Timestamp,
        unsupported_datatype => DataType::Unsupported(unsupported_datatype.into()),
    }
}

impl fmt::Display for DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataType::AtomicUrl => write!(f, "{}", urls::ATOMIC_URL),
            DataType::Date => write!(f, "{}", urls::DATE),
            DataType::Integer => write!(f, "{}", urls::INTEGER),
            DataType::Markdown => write!(f, "{}", urls::MARKDOWN),
            DataType::ResourceArray => write!(f, "{}", urls::RESOURCE_ARRAY),
            DataType::Slug => write!(f, "{}", urls::SLUG),
            DataType::String => write!(f, "{}", urls::STRING),
            DataType::Timestamp => write!(f, "{}", urls::TIMESTAMP),
            DataType::Unsupported(url) => write!(f, "{}", url),
        }
    }
}
