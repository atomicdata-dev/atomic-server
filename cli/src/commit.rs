use crate::Context;
use atomic_lib::{errors::AtomicResult, Storelike};

/// Apply a Commit using the Set method - create or update a value in a resource
pub fn set(context: &Context, subject: &str, property: &str, value: &str) -> AtomicResult<()> {
    // If the resource is not found, create it
    let mut resource = match context.store.get_resource(subject) {
        Ok(r) => r,
        Err(_) => atomic_lib::Resource::new(subject.into()),
    };
    resource.set_shortname(property, value, &context.store)?;
    resource.save(&context.store)?;
    Ok(())
}

/// Apply a Commit using the Set method, where the value is edited in the user's text editor.
#[cfg(feature = "native")]
pub fn edit(context: &Context, subject: &str, prop: &str) -> AtomicResult<()> {
    // If the resource is not found, create it
    let mut resource = match context.store.get_resource(subject) {
        Ok(r) => r,
        Err(_) => atomic_lib::Resource::new(subject.into()),
    };
    // If the prop is not found, create it
    let current_val = match resource.get_shortname(prop, &context.store) {
        Ok(val) => val.to_string(),
        Err(_) => "".to_string(),
    };
    let edited = edit::edit(current_val)?;
    // Remove newline - or else I can's save shortnames or numbers using vim;
    let trimmed = edited.trim_end_matches('\n');
    resource.set_shortname(prop, trimmed, &context.store)?;
    resource.save(&context.store)?;
    Ok(())
}

/// Apply a Commit using the Remove method - removes a property from a resource
pub fn remove(context: &Context, subject: &str, prop: &str) -> AtomicResult<()> {
    let mut resource = context.store.get_resource(subject)?;
    resource.remove_propval_shortname(prop, &context.store)?;
    resource.save(&context.store)?;
    Ok(())
}

/// Apply a Commit using the destroy method - removes a resource
pub fn destroy(context: &Context, subject: &str) -> AtomicResult<()> {
    let mut resource = context.store.get_resource(subject)?;
    resource.destroy(&context.store)?;
    Ok(())
}
