use atomic_lib::{
    errors::AtomicResult,
    serialize::{self, Format},
    Resource, Storelike,
};
use clap::ArgMatches;
use colored::*;

use crate::Context;

/// List of serialization options. Should match /path.rs/get
pub const SERIALIZE_OPTIONS: [&str; 7] =
    ["pretty", "json", "jsonld", "jsonad", "nt", "turtle", "n3"];

/// Returns preffered serialization format. Defaults to pretty.
pub fn get_serialization(argmatches: &ArgMatches) -> AtomicResult<Format> {
    let format = if let Some(preffered_format) = argmatches.value_of("as") {
        match preffered_format {
            "pretty" => (Format::PRETTY),
            "json" => (Format::JSON),
            "jsonld" => (Format::JSONLD),
            "jsonad" => (Format::JSONAD),
            "nt" => (Format::NT),
            "turtle" => (Format::NT),
            "n3" => (Format::NT),
            format => {
                return Err(
                    format!("As {} not supported. Try {:?}", format, SERIALIZE_OPTIONS).into(),
                );
            }
        }
    } else {
        Format::PRETTY
    };
    Ok(format)
}

/// Prints a resource for the terminal with readble formatting and colors
pub fn pretty_print_resource(resource: &Resource, store: &impl Storelike) -> AtomicResult<String> {
    let mut output = String::new();
    output.push_str(&*format!(
        "{0: <15}{1: <10} \n",
        "subject".blue().bold(),
        resource.get_subject()
    ));
    for (prop_url, val) in resource.get_propvals() {
        let prop_shortname = store.get_property(&prop_url)?.shortname;
        output.push_str(&*format!(
            "{0: <15}{1: <10} \n",
            prop_shortname.blue().bold(),
            val.to_string()
        ));
    }
    Ok(output)
}

/// Prints a resource to the command line
pub fn print_resource(
    context: &Context,
    resource: &Resource,
    argmatches: &ArgMatches,
) -> AtomicResult<()> {
    let out = match get_serialization(argmatches)? {
        Format::JSON => resource.to_json(&context.store)?,
        Format::JSONLD => resource.to_json_ld(&context.store)?,
        Format::JSONAD => resource.to_json_ad()?,
        Format::NT => serialize::atoms_to_ntriples(resource.to_atoms()?, &context.store)?,
        Format::PRETTY => pretty_print_resource(&resource, &context.store)?,
    };
    println!("{}", out);
    Ok(())
}
