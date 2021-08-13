use crate::{
    print::{get_serialization, print_resource},
    Context,
};
use atomic_lib::{errors::AtomicResult, serialize, storelike, Atom, Storelike};
use serialize::Format;

/// Resolves an Atomic Path query
pub fn get_path(context: &mut Context) -> AtomicResult<()> {
    let subcommand_matches = context.matches.subcommand_matches("get").unwrap();
    let path_vec: Vec<&str> = subcommand_matches
        .values_of("path")
        .expect("Add a URL, shortname or path")
        .collect();
    let path_string: String = path_vec.join(" ");
    let serialization: Format = get_serialization(subcommand_matches)?;

    // Returns a URL or Value
    let store = &mut context.store;
    let path = store.get_path(&path_string, Some(&context.mapping.lock().unwrap()))?;
    let out = match path {
        storelike::PathReturn::Subject(subject) => {
            let resource = store.get_resource_extended(&subject)?;
            print_resource(context, &resource, subcommand_matches)?;
            return Ok(());
        }
        storelike::PathReturn::Atom(atom) => match serialization {
            Format::JSONLD | Format::JSON | Format::JSONAD | Format::PRETTY => {
                atom.value.to_string()
            }
            Format::NT => {
                let atoms: Vec<Atom> = vec![*atom];
                serialize::atoms_to_ntriples(atoms, store)?
            }
        },
    };
    println!("{}", out);
    Ok(())
}
