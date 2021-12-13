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

/// Throws if not allowed.
/// Returns string with explanation if allowed.
pub fn check_write(
    store: &impl Storelike,
    resource: &Resource,
    for_agent: &str,
) -> AtomicResult<String> {
    check_rights(store, resource, for_agent, Right::Write)
}

/// Throws if not allowed.
/// Returns string with explanation if allowed.
pub fn check_read(
    store: &impl Storelike,
    resource: &Resource,
    for_agent: &str,
) -> AtomicResult<String> {
    check_rights(store, resource, for_agent, Right::Read)
}

/// Recursively checks a Resource and its Parents for rights.
/// Throws if not allowed.
/// Returns string with explanation if allowed.
pub fn check_rights(
    store: &impl Storelike,
    resource: &Resource,
    for_agent: &str,
    right: Right,
) -> AtomicResult<String> {
    if resource.get_subject() == for_agent {
        return Ok("Agents can always edit themselves or their children.".into());
    }

    // Check if the resource's write rights explicitly refers to the agent or the public agent
    if let Ok(arr_val) = resource.get(&right.to_string()) {
        for s in arr_val.to_subjects(None)? {
            match s.as_str() {
                urls::PUBLIC_AGENT => {
                    return Ok(format!(
                        "PublicAgent has been granted rights in {}",
                        resource.get_subject()
                    ))
                }
                agent => {
                    if agent == for_agent {
                        return Ok(format!(
                            "Write right has been explicitly set in {}",
                            resource.get_subject()
                        ));
                    }
                }
            };
        }
    }
    // Try the parents recursively
    if let Ok(parent_val) = resource.get(urls::PARENT) {
        match store.get_resource(&parent_val.to_string()) {
            Ok(parent) => {
                if resource.get_subject() == parent.get_subject() {
                    return Err(crate::errors::AtomicError::unauthorized(format!(
                        "There is a circular relationship in {} (parent = same resource).",
                        resource.get_subject()
                    )));
                }
                check_rights(store, &parent, for_agent, right)
            }
            Err(_err) => Err(crate::errors::AtomicError::unauthorized(format!(
                "Parent of {} ({}) not found: {}",
                resource.get_subject(),
                parent_val,
                _err
            ))),
        }
    } else {
        // resource has no parent and agent is not in Write array - check fails
        Err(crate::errors::AtomicError::unauthorized(
            "No right has been found in this resource or its parents".into(),
        ))
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
