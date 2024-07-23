//! Functions that can be valuable in multiple plugins

use crate::{errors::AtomicResult, urls, Resource, Value};

/// Returns a Resource with a description of "success"
pub fn return_success(message: &str) -> AtomicResult<Resource> {
    let mut resource = Resource::new("unknown".into());
    resource.set_unsafe(urls::DESCRIPTION.into(), Value::String(message.into()));
    resource.set_unsafe(urls::NAME.into(), Value::String("Success".into()));
    Ok(resource)
}