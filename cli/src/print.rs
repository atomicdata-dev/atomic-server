use atomic_lib::{
    errors::AtomicResult,
    serialize::{self, Format},
    Resource, Storelike,
};
use colored::*;

use crate::{Context, SerializeOptions};

/// Prints a resource for the terminal with readable formatting and colors
pub fn pretty_print_resource(resource: &Resource, store: &impl Storelike) -> AtomicResult<String> {
    let mut output = String::new();
    output.push_str(&format!(
        "{0: <15}{1: <10} \n",
        "subject".blue().bold(),
        resource.get_subject()
    ));
    for (prop_url, val) in resource.get_propvals() {
        let prop_shortname = store.get_property(prop_url)?.shortname;
        output.push_str(&format!(
            "{0: <15}{1: <10} \n",
            prop_shortname.blue().bold(),
            val
        ));
    }
    Ok(output)
}

/// Prints a resource to the command line
pub fn print_resource(
    context: &Context,
    resource: &Resource,
    serialize: &SerializeOptions,
) -> AtomicResult<()> {
    let format: Format = serialize.into();
    let out = match format {
        Format::Json => resource.to_json(&context.store)?,
        Format::JsonLd => resource.to_json_ld(&context.store)?,
        Format::JsonAd => resource.to_json_ad()?,
        Format::NTriples => serialize::atoms_to_ntriples(resource.to_atoms(), &context.store)?,
        Format::Pretty => pretty_print_resource(resource, &context.store)?,
    };
    println!("{}", out);
    Ok(())
}
