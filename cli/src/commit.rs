use crate::Context;
use atomic_lib::{errors::AtomicResult, Storelike};

/// Apply a Commit using the Set method - create or update a value in a resource
pub fn set(context: &Context) -> AtomicResult<()> {
    let subcommand = "set";
    let matches = context.matches.clone();
    let subcommand_matches = matches.subcommand_matches(subcommand).clone().unwrap();
    let subject = argument_to_url(context, subcommand, "subject")?;
    let prop = argument_to_string(context, subcommand, "property")?;
    let val = subcommand_matches.value_of("value").unwrap();
    let mut commit_builder = atomic_lib::commit::CommitBuilder::new(subject);
    commit_builder.set(prop, val.into());
    post(context, commit_builder)?;
    Ok(())
}

/// Apply a Commit using the Set method, where the value is edited in the user's text editor.
#[cfg(feature = "native")]
pub fn edit(context: &Context) -> AtomicResult<()> {
    let subcommand = "edit";
    let subject = argument_to_url(context, subcommand, "subject")?;
    let prop = argument_to_string(context, subcommand, "property")?;
    let current_val = context
        .store
        .get_resource(&subject)?
        .get_shortname(&prop, &context.store)?
        .to_string();
    let edited = edit::edit(current_val)?;
    let mut commit_builder = atomic_lib::commit::CommitBuilder::new(subject);
    commit_builder.set(prop, edited);
    post(context, commit_builder)?;
    Ok(())
}

/// Apply a Commit using the Remove method - removes a property from a resource
pub fn remove(context: &Context) -> AtomicResult<()> {
    let subcommand = "remove";
    let subject = argument_to_url(context, subcommand, "subject")?;
    let prop = argument_to_string(context, subcommand, "property")?;
    let mut commit_builder = atomic_lib::commit::CommitBuilder::new(subject);
    commit_builder.remove(prop);
    post(context, commit_builder)?;
    Ok(())
}

/// Apply a Commit using the destroy method - removes a resource
pub fn destroy(context: &Context) -> AtomicResult<()> {
    let subcommand = "destroy";
    let subject = argument_to_url(context, subcommand, "subject")?;
    let mut commit_builder = atomic_lib::commit::CommitBuilder::new(subject);
    commit_builder.destroy(true);
    post(context, commit_builder)?;
    Ok(())
}

/// Posts the Commit and applies it to the server
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

fn argument_to_string(context: &Context, subcommand: &str, argument: &str) -> AtomicResult<String> {
    let subcommand_matches = context.matches.subcommand_matches(subcommand).unwrap();
    let user_arg = subcommand_matches
        .value_of(argument)
        .ok_or(format!("No argument value for {} found", argument))?;
    Ok(user_arg.into())
}

/// Parses a single argument (URL or Bookmark), should return a valid URL
fn argument_to_url(context: &Context, subcommand: &str, argument: &str) -> AtomicResult<String> {
    let subcommand_matches = context.matches.subcommand_matches(subcommand).unwrap();
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
