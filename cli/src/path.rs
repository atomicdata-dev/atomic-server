use crate::{pretty_print_resource, Context};
use atomic_lib::{storelike, serialize, Storelike, errors::AtomicResult, Atom};

/// Resolves an Atomic Path query
pub fn get(context: &mut Context) -> AtomicResult<()> {
  let subcommand_matches = context.matches.subcommand_matches("get").unwrap();
  let path_string = subcommand_matches
      .value_of("path")
      .expect("Add a URL, shortname or path");
  let serialization: Option<serialize::SerialializationFormats> =
      match subcommand_matches.value_of("as") {
          Some("json") => Some(serialize::SerialializationFormats::JSON),
          Some("jsonld") => Some(serialize::SerialializationFormats::JSONLD),
          Some("ad3") => Some(serialize::SerialializationFormats::AD3),
          Some("nt") => Some(serialize::SerialializationFormats::NT),
          Some("turtle") => Some(serialize::SerialializationFormats::NT),
          Some("n3") => Some(serialize::SerialializationFormats::NT),
          Some(format) => {
              panic!("As {} not supported. Try 'json' or 'ad3'.", format);
          }
          None => None,
      };

  // Returns a URL or Value
  let result = &context.store.get_path(path_string, &context.mapping);
  match result {
      Ok(res) => match res {
          storelike::PathReturn::Subject(subject) => match serialization {
              Some(serialize::SerialializationFormats::JSON) => {
                  let out = &context.store.resource_to_json(&subject, 1, false)?;
                  println!("{}", out);
              }
              Some(serialize::SerialializationFormats::JSONLD) => {
                  let out = &context.store.resource_to_json(&subject, 1, true)?;
                  println!("{}", out);
              }
              Some(serialize::SerialializationFormats::AD3) => {
                  let out = &context.store.resource_to_ad3(&subject, None)?;
                  println!("{}", out);
              }
              Some(serialize::SerialializationFormats::NT) => {
                  println!("subject: {}", &subject);
                  let atoms = context.store.tpf(Some(&subject), None, None)?;
                  let out = serialize::serialize_atoms_to_n_triples(atoms, &context.store)?;
                  println!("{}", out);
              }
              None => {
                  pretty_print_resource(&subject, &context.store).unwrap();
              }
          },
          storelike::PathReturn::Atom(atom) => match serialization {
              Some(serialize::SerialializationFormats::JSONLD)
              | Some(serialize::SerialializationFormats::JSON) => {
                  println!("{}", atom.value);
              }
              Some(serialize::SerialializationFormats::AD3) => {
                  println!("{}", atom.value);
              }
              Some(serialize::SerialializationFormats::NT) => {
                  let mut atoms: Vec<Atom> = Vec::new();
                  atoms.push(atom.into());
                  let out = serialize::serialize_atoms_to_n_triples(atoms.into(), &context.store)?;
                  println!("{}", out);
              }
              None => println!("{:?}", &atom.native_value),
          },
      },
      Err(e) => {
          eprintln!("{}", e);
      }
  };
  Ok(())
}
