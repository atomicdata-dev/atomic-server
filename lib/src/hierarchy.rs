//! The Hierarchy model describes how Resources are structed in a tree-like shape.
//! It deals with authorization (read / write permissions, rights, grants)
//! See

use core::fmt;

use crate::{errors::AtomicResult, urls, Resource, Storelike, Value};

#[derive(Debug)]
pub enum Right {
    /// Full read access to the resource and its children.
    /// https://atomicdata.dev/properties/read
    Read,
    /// Full edit, update, destroy access to the resource and its children.
    /// https://atomicdata.dev/properties/write
    Write,
    /// Create new children (append to tree)
    /// https://atomicdata.dev/properties/append
    Append,
}

impl fmt::Display for Right {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let str = match self {
            Right::Read => urls::READ,
            Right::Write => urls::WRITE,
            Right::Append => urls::APPEND,
        };
        fmt.write_str(str)
    }
}

/// Looks for children relations, adds to the resource. Performs a TPF query, might be expensive.
pub fn add_children(store: &impl Storelike, resource: &mut Resource) -> AtomicResult<Resource> {
    let atoms = store.tpf(
        None,
        Some(urls::PARENT),
        Some(&Value::AtomicUrl(resource.get_subject().into())),
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

/// Does the Agent have the right to read / view the properties of the selected resource, or any of its parents?
/// Throws if not allowed.
/// Returns string with explanation if allowed.
pub fn check_read(
    store: &impl Storelike,
    resource: &Resource,
    for_agent: &str,
) -> AtomicResult<String> {
    check_rights(store, resource, for_agent, Right::Read)
}

/// Does the Agent have the right to _append_ to its parent?
/// This checks the `append` rights, and if that fails, checks the `write` right.
/// Throws if not allowed.
/// Returns string with explanation if allowed.
pub fn check_append(
    store: &impl Storelike,
    resource: &Resource,
    for_agent: &str,
) -> AtomicResult<String> {
    let parent = resource.get_parent(store)?;
    if let Ok(msg) = check_rights(store, &parent, for_agent, Right::Append) {
        Ok(msg)
    } else {
        check_rights(store, resource, for_agent, Right::Write)
    }
}

/// Recursively checks a Resource and its Parents for rights.
/// Throws if not allowed.
/// Returns string with explanation if allowed.
#[tracing::instrument(skip(store, resource))]
pub fn check_rights(
    store: &impl Storelike,
    resource: &Resource,
    for_agent: &str,
    right: Right,
) -> AtomicResult<String> {
    if resource.get_subject() == for_agent {
        return Ok("Agents can always edit themselves or their children.".into());
    }

    // Handle Commits.
    if let Ok(commit_subject) = resource.get(urls::SUBJECT) {
        return match right {
            Right::Read => {
                // Commits can be read when their subject / target is readable.
                let target = store.get_resource(&commit_subject.to_string())?;
                check_rights(store, &target, for_agent, right)
            }
            Right::Write => Err("Commits cannot be edited.".into()),
            Right::Append => Err("Commits cannot have children, you cannot Append to them.".into()),
        };
    }

    // Check if the resource's rights explicitly refers to the agent or the public agent
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
                            "Right has been explicitly set in {}",
                            resource.get_subject()
                        ));
                    }
                }
            };
        }
    }

    // Try the parents recursively
    if let Ok(parent) = resource.get_parent(store) {
        check_rights(store, &parent, for_agent, right)
    } else {
        let for_string = if for_agent == urls::PUBLIC_AGENT {
            "the Public Agent".to_string()
        } else {
            for_agent.to_string()
        };
        // resource has no parent and agent is not in rights array - check fails
        Err(crate::errors::AtomicError::unauthorized(format!(
            "No {} right has been found for {} in this resource or its parents",
            right, for_string
        )))
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
