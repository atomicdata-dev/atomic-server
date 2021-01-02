use crate::{pretty_print_resource, Context};
use atomic_lib::{storelike, serialize, Storelike, errors::AtomicResult, Atom};
use serialize::Format;

/// List of serialization options. Should match /path.rs/get
pub const SERIALIZE_OPTIONS: [&str; 7] = ["pretty", "json", "jsonld", "ad3", "nt", "turtle", "n3"];

/// Resolves an Atomic Path query
pub fn get_path(context: &mut Context) -> AtomicResult<()> {
  let subcommand_matches = context.matches.subcommand_matches("get").unwrap();
  let path_string = subcommand_matches
      .value_of("path")
      .expect("Add a URL, shortname or path");
  let serialization: Format =
      match subcommand_matches.value_of("as").unwrap() {
          "pretty" => (Format::PRETTY),
          "json" => (Format::JSON),
          "jsonld" => (Format::JSONLD),
          "ad3" => (Format::AD3),
          "nt" => (Format::NT),
          "turtle" => (Format::NT),
          "n3" => (Format::NT),
          format => {
              return Err(format!("As {} not supported. Try 'json' or 'ad3'.", format).into());
          }
      };

  // Returns a URL or Value
  let result = context.store.get_path(path_string, Some(&context.mapping.lock().unwrap()));
  let store = &mut context.store;
  match result {
      Ok(res) => match res {
          storelike::PathReturn::Subject(subject) => match serialization {
              Format::JSON => {
                  let out = store.get_resource_extended(&subject)?.to_json(store, 1, false)?;
                  println!("{}", out);
              }
              Format::JSONLD => {
                  let out = store.get_resource_extended(&subject)?.to_json(store, 1, true)?;
                  println!("{}", out);
              }
              Format::AD3 => {
                  let out = store.get_resource_extended(&subject)?.to_ad3()?;
                  println!("{}", out);
              }
              Format::NT => {
                //   let atoms = store.tpf(Some(&subject), None, None)?;
                  let resource = store.get_resource_extended(&subject)?;
                  let out = serialize::atoms_to_ntriples(resource.to_atoms()?, store)?;
                  println!("{}", out);
              }
              Format::PRETTY => {
                  pretty_print_resource(&subject, store)?;
              }
          },
          storelike::PathReturn::Atom(atom) => match serialization {
              Format::JSONLD
              | Format::JSON => {
                  println!("{}", atom.value);
              }
              Format::AD3 => {
                  println!("{}", atom.value);
              }
              Format::NT => {
                  let mut atoms: Vec<Atom> = Vec::new();
                  atoms.push(Atom::from(*atom));
                  let out = serialize::atoms_to_ntriples(atoms, store)?;
                  println!("{}", out);
              }
              Format::PRETTY => println!("{:?}", &atom.native_value),
          },
      },
      Err(e) => {
          eprintln!("{}", e);
      }
  };
  Ok(())
}
