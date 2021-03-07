//! Endpoints are experimental plugin-like objects, that allow for dynamic resources.
//! An endpoint is a resource that accepts one or more query parameters, and returns a resource that is probably calculated at runtime.
//! Examples of endpoints are versions for resources, or (pages for) collections

use crate::{Resource, Storelike, Value, errors::AtomicResult, schema::Property, urls, versioning::versioning_endpoint};

/// An API endpoint at some path which accepts requests and returns some Resource.
pub struct Endpoint {
  /// The part behind the server domain, e.g. '/versions' or '/collections'. Include the slash.
  pub path: String,
  /// A list of arguments that can be passed to the Endpoint
  pub params: Vec<Property>,
  pub description: String,
  pub shortname: String,
  // This requires using dyn, which is not possible with the :Sized Storelike trait
  // pub handler: fn(subject: String, store: &dyn Storelike) -> AtomicResult<Resource>,
}

  impl Endpoint {
  pub fn to_resource(&self, store: &impl Storelike) -> AtomicResult<Resource> {
    let subject = format!("{}{}", store.get_base_url(), self.path);
    let mut resource = Resource::new(subject);
    resource.set_propval_string(urls::DESCRIPTION.into(), &self.description, store)?;
    resource.set_propval_string(urls::SHORTNAME.into(), &self.shortname, store)?;
    let params_vec: Vec<String> = self.params.clone().into_iter().map(|prop| prop.subject).collect();
    resource.set_propval(urls::ENDPOINT_PARAMETERS.into(), Value::from(params_vec), store)?;
    Ok(resource)
  }
}

pub fn default_endpoints() -> Vec<Endpoint> {
  let mut vec = Vec::new();
  vec.push(versioning_endpoint());
  vec
}
