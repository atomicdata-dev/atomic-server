//! Functions that can be valuable in multiple plugins

use crate::{errors::AtomicResult, urls, Resource, Value};

/// Returns a Resource with a description of "success"
pub fn return_success() -> AtomicResult<Resource> {
    let mut resource = Resource::new("unknown".into());
    resource.set_propval_unsafe(urls::DESCRIPTION.into(), Value::String("success".into()));
    Ok(resource)
}
