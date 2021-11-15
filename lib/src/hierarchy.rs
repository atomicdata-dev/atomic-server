//! The Hierarchy model describes how Resources are structed in a tree-like shape.
//! It dealt with authorization (read / write grants)

use core::fmt;

use crate::{errors::AtomicResult, urls, Resource, Storelike};

pub enum Right {
    Read,
    Write,
}

impl fmt::Display for Right {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let str = match self {
            Right::Read => urls::READ,
            Right::Write => urls::WRITE,
        };
        fmt.write_str(str)
    }
}

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
    children.sort();
    resource.set_propval(urls::CHILDREN.into(), children.into(), store)?;
    Ok(resource.to_owned())
}

pub fn check_write(
    store: &impl Storelike,
    resource: &Resource,
    for_agent: &str,
) -> AtomicResult<bool> {
    check_rights(store, resource, for_agent, Right::Write)
}

pub fn check_read(
    store: &impl Storelike,
    resource: &Resource,
    for_agent: &str,
) -> AtomicResult<bool> {
    check_rights(store, resource, for_agent, Right::Read)
}

/// Recursively checks a Resource and its Parents for rights.
pub fn check_rights(
    store: &impl Storelike,
    resource: &Resource,
    for_agent: &str,
    right: Right,
) -> AtomicResult<bool> {
    // Check if the resource's write rights explicitly refers to the agent
    if let Ok(arr_val) = resource.get(&right.to_string()) {
        if arr_val.to_subjects(None)?.iter().any(|s| s == for_agent) {
            return Ok(true);
        };
    }
    // Try the parents recursively
    if let Ok(val) = resource.get(urls::PARENT) {
        let parent = store.get_resource(&val.to_string())?;
        if resource.get_subject() == parent.get_subject() {
            // return Err(format!("Parent ({}) is the same as the current resource - there is a circular parent relationship.", val).into());
            return Ok(false);
        }
        check_rights(store, &parent, for_agent, right)
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
        commitbuilder_1.set(property.into(), value);
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

    #[test]
    fn display_right() {
        let read = super::Right::Read;
        assert_eq!(read.to_string(), super::urls::READ);
        let write = super::Right::Write;
        assert_eq!(write.to_string(), super::urls::WRITE);
    }
}
