//! The Hierarchy model describes how Resources are structed in a tree-like shape.
//! It dealt with authorization (read / write grants)

use crate::{Resource, Storelike, errors::AtomicResult, urls};

/// Looks for children relations, adds to the resource. Performs a TPF query, might be expensive.
pub fn add_children(
  store: &impl Storelike,
  resource: &mut Resource,
) -> AtomicResult<Resource> {
  let atoms = store.tpf(None, Some(urls::PARENT), Some(resource.get_subject()), false)?;
  let mut children: Vec<String> = Vec::new();
  for atom in atoms {
    children.push(atom.subject)
  }
  resource.set_propval(urls::CHILDREN.into(), children.into(), store)?;
  Ok(resource.to_owned())
}

/// Recursively checks a Resource and its Parents for write.
pub fn check_write(
  store: &impl Storelike,
  resource: &Resource,
  agent: String,
) -> AtomicResult<bool> {
  // Check if the resource's write rights explicitly refers to the agent
  if let Ok(arr_val) = resource.get(urls::WRITE) {
    if arr_val.to_vec()?.contains(&agent) {
      return Ok(true)
    };
  }
  // Try the parents recursively
  if let Ok(val) = resource.get(urls::PARENT) {
    let parent = store.get_resource(&val.to_string())?;
    check_write(store, &parent, agent)
  } else {
    // resource has no parent and agent is not in Write array - check fails
    Ok(false)
  }
}
