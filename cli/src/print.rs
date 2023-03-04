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

/// Returns preferred serialization format. Defaults to pretty.
pub fn get_serialization(argmatches: &ArgMatches) -> AtomicResult<Format> {
    let format = if let Some(preferred_format) = argmatches.get_one::<String>("as") {
        match preferred_format.as_str() {
            "pretty" => Format::Pretty,
            "json" => Format::Json,
            "jsonld" => Format::JsonLd,
            "jsonad" => Format::JsonAd,
            "nt" => Format::NTriples,
            "turtle" => Format::NTriples,
            "n3" => Format::NTriples,
            format => {
                return Err(
                    format!("As {} not supported. Try {:?}", format, SERIALIZE_OPTIONS).into(),
                );
            }
        }
    } else {
        Format::Pretty
    };
    Ok(format)
}

/// Prints a resource for the terminal with readble formatting and colors
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
    argmatches: &ArgMatches,
) -> AtomicResult<()> {
    let out = match get_serialization(argmatches)? {
        Format::Json => resource.to_json(&context.store)?,
        Format::JsonLd => resource.to_json_ld(&context.store)?,
        Format::JsonAd => resource.to_json_ad()?,
        Format::NTriples => serialize::atoms_to_ntriples(resource.to_atoms(), &context.store)?,
        Format::Pretty => pretty_print_resource(resource, &context.store)?,
    };
    println!("{}", out);
    Ok(())
}
