use crate::{Context, delta::argument_to_url};
use atomic_lib::{errors::AtomicResult};

/// Perfoprm a Commit using the Set method - create or update a resource
pub fn set(context: &mut Context) -> AtomicResult<()> {
    let subcommand_matches = context.matches.subcommand_matches("set").unwrap();
    let subject = argument_to_url(context, "set", "subject")?;
    let property = argument_to_url(context, "set", "subject")?;
    let value = subcommand_matches.value_of("value").unwrap();

    // let resource = context.store.get_resource_extended(&subject)?;
    // resource.set_by_shortname(&property, &value)?;
    // resource.save();
    // let signer = context.author_subject;
    let (signer, private_key, base_url) = get_write_props(context)?;
    let commit_builder = atomic_lib::commit::CommitBuilder::new(subject, signer);
    let commit = commit_builder.sign(&private_key)?;
    atomic_lib::client::post_commit(&base_url, &commit)?;
    Ok(())
}

/// Returns the optional Author, Private Key, Base Url
pub fn get_write_props(context: &mut Context) -> AtomicResult<(String, String, String)> {
    if let Some(signer) = context.author_subject {
        if let Some(private_key) = context.author_private_key {
            if let Some(base_url) = context.base_url {
                Ok((signer, private_key, base_url))
            } else {
                Err("No Base URL.".into())
            }
        } else {
            Err("No Private Key set.".into())
        }
    } else {
        Err("No default Author set.".into())
    }
}
