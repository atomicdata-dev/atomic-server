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
        Err(_) => atomic_lib::Resource::new(subject),
    };
    resource.set_propval_shortname(&property, &value, &context.store)?;
    resource.save(&context.store)?;
    Ok(())
}

/// Apply a Commit using the Set method, where the value is edited in the user's text editor.
#[cfg(feature = "native")]
pub fn edit(context: &Context) -> AtomicResult<()> {
    let subject = argument_to_url(context, "subject")?;
    let prop = argument_to_string(context, "property")?;
    // If the resource is not found, create it
    let mut resource = match context.store.get_resource(&subject) {
        Ok(r) => r,
        Err(_) => atomic_lib::Resource::new(subject),
    };
    // If the prop is not found, create it
    let current_val = match resource.get_shortname(&prop, &context.store) {
        Ok(val) => val.to_string(),
        Err(_) => "".to_string(),
    };
    let edited = edit::edit(current_val)?;
    // Remove newline - or else I can's save shortnames or numbers using vim;
    let trimmed = edited.trim_end_matches('\n');
    resource.set_propval_shortname(&prop, trimmed, &context.store)?;
    resource.save(&context.store)?;
    Ok(())
}

/// Apply a Commit using the Remove method - removes a property from a resource
pub fn remove(context: &Context) -> AtomicResult<()> {
    let subject = argument_to_url(context, "subject")?;
    let prop = argument_to_string(context, "property")?;
    let mut resource = context.store.get_resource(&subject)?;
    resource.remove_propval_shortname(&prop, &context.store)?;
    resource.save(&context.store)?;
    Ok(())
}

/// Apply a Commit using the destroy method - removes a resource
pub fn destroy(context: &Context) -> AtomicResult<()> {
    let subject = argument_to_url(context, "subject")?;
    let mut resource = context.store.get_resource(&subject)?;
    resource.destroy(&context.store)?;
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
