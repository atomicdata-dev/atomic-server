//! Endpoints are experimental plugin-like objects, that allow for dynamic resources.
//! An endpoint is a resource that accepts one or more query parameters, and returns a resource that is probably calculated at runtime.
//! Examples of endpoints are versions for resources, or (pages for) collections

use crate::{
    errors::AtomicResult,
    plugins::{
        path::path_endpoint,
        versioning::{all_versions_endpoint, version_endpoint},
    },
    urls, Db, Resource, Storelike, Value,
};

/// An API endpoint at some path which accepts requests and returns some Resource.
pub struct Endpoint {
    /// The part behind the server domain, e.g. '/versions' or '/collections'. Include the slash.
    pub path: String,
    /// The function that is called when the request matches the path
    pub handle:
        fn(subject: url::Url, store: &Db, for_agent: Option<String>) -> AtomicResult<Resource>,
    /// The list of properties that can be passed to the Endpoint as Query parameters
    pub params: Vec<String>,
    pub description: String,
    pub shortname: String,
}

impl Endpoint {
    /// Converts Endpoint to resource. Does not save it.
    pub fn to_resource(&self, store: &impl Storelike) -> AtomicResult<Resource> {
        let subject = format!("{}{}", store.get_base_url(), self.path);
        let mut resource = Resource::new(subject);
        resource.set_propval_string(urls::DESCRIPTION.into(), &self.description, store)?;
        resource.set_propval_string(urls::SHORTNAME.into(), &self.shortname, store)?;
        let is_a = [urls::ENDPOINT.to_string()].to_vec();
        resource.set_propval(urls::IS_A.into(), is_a.into(), store)?;
        let params_vec: Vec<String> = self.params.clone();
        resource.set_propval(
            urls::ENDPOINT_PARAMETERS.into(),
            Value::from(params_vec),
            store,
        )?;
        Ok(resource)
    }
}

pub fn default_endpoints() -> Vec<Endpoint> {
    vec![version_endpoint(), all_versions_endpoint(), path_endpoint()]
}
