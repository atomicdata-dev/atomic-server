use crate::{Context, delta::argument_to_url};
use atomic_lib::{errors::AtomicResult};

/// Perfoprm a Commit using the Set method - create or update a resource
pub fn set(context: &mut Context) -> AtomicResult<()> {
    let subcommand_matches = context.matches.subcommand_matches("set").unwrap();
    let subject = argument_to_url(context, "set", "subject")?;
    let prop = argument_to_url(context, "set", "property")?;
    let val = subcommand_matches.value_of("value").unwrap();

    // let resource = context.store.get_resource_extended(&subject)?;
    // resource.set_by_shortname(&property, &value)?;
    // resource.save();
    // let signer = context.author_subject;
    let write_ctx = context.get_write_context();
    let mut commit_builder = atomic_lib::commit::CommitBuilder::new(subject, write_ctx.author_subject);
    commit_builder.set(prop, val.into());
    let commit = commit_builder.sign(&write_ctx.author_private_key)?;
    println!("{:?}", commit);
    atomic_lib::client::post_commit(&format!("{}commit", &write_ctx.base_url), &commit)?;
    Ok(())
}
