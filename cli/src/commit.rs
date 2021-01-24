use crate::Context;
use atomic_lib::{errors::AtomicResult, Storelike};

/// Apply a Commit using the Set method - create or update a value in a resource
pub fn set(context: &Context) -> AtomicResult<()> {
    let subject = argument_to_url(context, "subject")?;
    let property = argument_to_string(context, "property")?;
    let value = argument_to_string(context, "value")?;

    // If the resource is not found, create it
    let mut resource = match context.store.get_resource(&subject) {
        Ok(r) => r,
        Err(_) => {
            atomic_lib::Resource::new(subject)
        }
    };
    resource.set_propval_shortname(&property, &value, &context.store)?;
    post(context, resource.get_commit_builder().clone())?;
    Ok(())
}

/// Apply a Commit using the Set method, where the value is edited in the user's text editor.
#[cfg(feature = "native")]
pub fn edit(context: &Context) -> AtomicResult<()> {
    let subject = argument_to_url(context, "subject")?;
    let prop = argument_to_string(context,  "property")?;
    let mut resource = context.store.get_resource(&subject)?;
    let current_val = resource.get_shortname(&prop, &context.store)?.to_string();
    let edited = edit::edit(current_val)?;
    resource.set_propval_shortname(&prop, &edited, &context.store)?;
    post(context, resource.get_commit_builder().clone())?;
    Ok(())
}

/// Apply a Commit using the Remove method - removes a property from a resource
pub fn remove(context: &Context) -> AtomicResult<()> {
    let subject = argument_to_url(context, "subject")?;
    let prop = argument_to_string(context, "property")?;
    let mut resource = context.store.get_resource(&subject)?;
    resource.remove_propval_shortname(&prop, &context.store)?;
    post(context, resource.get_commit_builder().clone())?;
    Ok(())
}

/// Apply a Commit using the destroy method - removes a resource
pub fn destroy(context: &Context) -> AtomicResult<()> {
    let subject = argument_to_url(context, "subject")?;
    let mut commit_builder = atomic_lib::commit::CommitBuilder::new(subject);
    commit_builder.destroy(true);
    post(context, commit_builder)?;
    Ok(())
}

/// Signs the Commit, Posts it and applies it to the server
fn post(context: &Context, commit_builder: atomic_lib::commit::CommitBuilder) -> AtomicResult<()> {
    context.get_write_context();
    let agent = context
        .store
        .get_default_agent()
        .expect("No default agent set");
    let commit = commit_builder.sign(&agent)?;
    atomic_lib::client::post_commit(&commit)?;
    Ok(())
}

/// Parses a single argument as string
fn argument_to_string(context: &Context, argument: &str) -> AtomicResult<String> {
    let command_name = context.matches.subcommand_name().unwrap();
    let subcommand_matches = context.matches.subcommand_matches(command_name).unwrap();
    let user_arg = subcommand_matches
        .value_of(argument)
        .ok_or(format!("No argument value for {} found", argument))?;
    Ok(user_arg.into())
}

/// Parses a single argument (URL or Bookmark), should return a valid URL
fn argument_to_url(context: &Context, argument: &str) -> AtomicResult<String> {
    let command_name = context.matches.subcommand_name().unwrap();
    let subcommand_matches = context.matches.subcommand_matches(command_name).unwrap();
    let user_arg = subcommand_matches
        .value_of(argument)
        .ok_or(format!("No argument value for {} found", argument))?;
    let id_url: String = context
        .mapping
        .lock()
        .unwrap()
        .try_mapping_or_url(&String::from(user_arg))
        .ok_or(&*format!("No url found for {}", user_arg))?;
    Ok(id_url)
}
