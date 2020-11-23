use crate::{Context, delta::argument_to_url};
use atomic_lib::{errors::AtomicResult};

/// Apply a Commit using the Set method - create or update a value in a resource
pub fn set(context: &Context) -> AtomicResult<()> {
    let subcommand = "set";
    let subcommand_matches = context.matches.subcommand_matches(subcommand).clone().unwrap();
    let subject = argument_to_url(context, subcommand, "subject")?;
    let prop = argument_to_url(context, subcommand, "property")?;
    let val = subcommand_matches.value_of("value").unwrap();
    let mut commit_builder = builder(context, subject);
    commit_builder.set(prop, val.into());
    post(context, commit_builder)?;
    Ok(())
}

/// Apply a Commit using the Remove method - removes a property from a resource
pub fn remove(context: &Context) -> AtomicResult<()> {
    let subcommand = "remove";
    let subject = argument_to_url(context, subcommand, "subject")?;
    let prop = argument_to_url(context, subcommand, "property")?;
    let mut commit_builder = builder(context, subject);
    commit_builder.remove(prop);
    post(context, commit_builder)?;
    Ok(())
}

/// Apply a Commit using the destroy method - removes a resource
pub fn destroy(context: &Context) -> AtomicResult<()> {
    let subcommand = "destroy";
    let subject = argument_to_url(context, subcommand, "subject")?;
    let mut commit_builder = builder(context, subject);
    commit_builder.destroy(true);
    post(context, commit_builder)?;
    Ok(())
}

fn builder(context: &Context, subject: String) -> atomic_lib::commit::CommitBuilder {
    let write_ctx = context.get_write_context();
    atomic_lib::commit::CommitBuilder::new(subject, write_ctx.author_subject)
}

/// Posts the Commit and applies it to the server
fn post(context: &Context , commit_builder: atomic_lib::commit::CommitBuilder) -> AtomicResult<()> {
    let write_ctx = context.get_write_context();
    let commit = commit_builder.sign(&write_ctx.author_private_key)?;
    atomic_lib::client::post_commit(&format!("{}commit", &write_ctx.base_url), &commit)?;
    Ok(())
}
