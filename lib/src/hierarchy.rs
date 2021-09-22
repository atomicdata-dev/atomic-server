//! The Hierarchy model describes how Resources are structed in a tree-like shape.
//! It dealt with authorization (read / write grants)

use crate::{errors::AtomicResult, urls, Resource, Storelike};

/// Looks for children relations, adds to the resource. Performs a TPF query, might be expensive.
pub fn add_children(store: &impl Storelike, resource: &mut Resource) -> AtomicResult<Resource> {
    let atoms = store.tpf(
        None,
        Some(urls::PARENT),
        Some(resource.get_subject()),
        false,
    )?;
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
            return Ok(true);
        };
    }
    // Try the parents recursively
    if let Ok(val) = resource.get(urls::PARENT) {
        let parent = store.get_resource(&val.to_string())?;
        if resource.get_subject() == parent.get_subject() {
            return Err(format!("Parent ({}) is the same as the current resource", val).into());
        }
        check_write(store, &parent, agent)
    } else {
        // resource has no parent and agent is not in Write array - check fails
        Ok(false)
    }
}

#[cfg(test)]
mod test {
    // use super::*;
    use crate::{datatype::DataType, Storelike, Value};

    // TODO: Add tests for:
    // - basic check_write (should be false for newly created agent)
    // - Malicious Commit (which grants itself write rights)

    #[test]
    fn authorization() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        // let agent = store.create_agent(Some("test_actor")).unwrap();
        let subject = "https://localhost/new_thing";
        let mut commitbuilder_1 = crate::commit::CommitBuilder::new(subject.into());
        let property = crate::urls::DESCRIPTION;
        let value = Value::new("Some value", &DataType::Markdown).unwrap();
        commitbuilder_1.set(property.into(), value.clone());
        // let mut commitbuilder_2 = commitbuilder_1.clone();
        // let commit_1 = commitbuilder_1.sign(&agent, &store).unwrap();
        // Should fail if there is no self_url set in the store, and no parent in the commit
        // TODO: FINISH THIS
        // commit_1.apply_opts(&store, true, true, true, true).unwrap_err();
        // commitbuilder_2.set(crate::urls::PARENT.into(), Value::AtomicUrl(crate::urls::AGENT.into()));
        // let commit_2 = commitbuilder_2.sign(&agent, &store).unwrap();

        // let resource = store.get_resource(&subject).unwrap();
        // assert!(resource.get(property).unwrap().to_string() == value.to_string());
    }
}
