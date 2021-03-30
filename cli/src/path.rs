use crate::{pretty_print_resource, Context};
use atomic_lib::{errors::AtomicResult, serialize, storelike, Atom, Storelike};
use serialize::Format;

/// List of serialization options. Should match /path.rs/get
pub const SERIALIZE_OPTIONS: [&str; 8] = ["pretty", "json", "jsonld", "jsonad", "ad3", "nt", "turtle", "n3"];

/// Resolves an Atomic Path query
pub fn get_path(context: &mut Context) -> AtomicResult<()> {
    let subcommand_matches = context.matches.subcommand_matches("get").unwrap();
    let path_vec: Vec<&str> = subcommand_matches
        .values_of("path")
        .expect("Add a URL, shortname or path")
        .collect();
    let path_string: String = path_vec.join(" ");
    let serialization: Format = match subcommand_matches.value_of("as").unwrap() {
        "pretty" => (Format::PRETTY),
        "json" => (Format::JSON),
        "jsonld" => (Format::JSONLD),
        "jsonad" => (Format::JSONAD),
        "ad3" => (Format::AD3),
        "nt" => (Format::NT),
        "turtle" => (Format::NT),
        "n3" => (Format::NT),
        format => {
            return Err(format!("As {} not supported. Try 'json' or 'ad3'.", format).into());
        }
    };

    // Returns a URL or Value
    let store = &mut context.store;
    let path = store
        .get_path(&path_string, Some(&context.mapping.lock().unwrap()))?;
    let out = match path {
        storelike::PathReturn::Subject(subject) => match serialization {
            Format::JSON => store
                .get_resource_extended(&subject)?
                .to_json(store)?,
            Format::JSONLD => store
                .get_resource_extended(&subject)?
                .to_json_ld(store)?,
            Format::JSONAD => store
                .get_resource_extended(&subject)?
                .to_json_ad(store)?,
            Format::AD3 => store.get_resource_extended(&subject)?.to_ad3()?,
            Format::NT => {
                let resource = store.get_resource_extended(&subject)?;
                serialize::atoms_to_ntriples(resource.to_atoms()?, store)?
            }
            Format::PRETTY => pretty_print_resource(&subject, store)?,
        },
        storelike::PathReturn::Atom(atom) => match serialization {
            Format::JSONLD | Format::JSON | Format::JSONAD => {
                atom.value
            }
            Format::AD3 => {
                atom.value
            }
            Format::NT => {
                let mut atoms: Vec<Atom> = Vec::new();
                atoms.push(Atom::from(*atom));
                serialize::atoms_to_ntriples(atoms, store)?
            }
            Format::PRETTY => atom.native_value.to_string(),
        },
    };
    println!("{}", out);
    Ok(())
}
