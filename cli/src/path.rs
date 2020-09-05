use crate::{pretty_print_resource, Context};
use atomic_lib::{storelike, serialize, Storelike};

/// Resolves an Atomic Path query
pub fn get(context: &mut Context) {
  let subcommand_matches = context.matches.subcommand_matches("get").unwrap();
  let path_string = subcommand_matches
      .value_of("path")
      .expect("Add a URL, shortname or path");
  let serialization: Option<serialize::SerialializationFormats> =
      match subcommand_matches.value_of("as") {
          Some("json") => Some(serialize::SerialializationFormats::JSON),
          Some("jsonld") => Some(serialize::SerialializationFormats::JSONLD),
          Some("ad3") => Some(serialize::SerialializationFormats::AD3),
          Some(format) => {
              panic!("As {} not supported. Try 'json' or 'ad3'.", format);
          }
          None => None,
      };

  // Returns a URL or Value
  let result = &context.store.get_path(path_string, &context.mapping);
  match result {
      Ok(res) => match res {
          storelike::PathReturn::Subject(url) => match serialization {
              Some(serialize::SerialializationFormats::JSON) => {
                  let out = &context.store.resource_to_json(&url, 1, false).unwrap();
                  println!("{}", out);
              }
              Some(serialize::SerialializationFormats::JSONLD) => {
                  let out = &context.store.resource_to_json(&url, 1, true).unwrap();
                  println!("{}", out);
              }
              Some(serialize::SerialializationFormats::AD3) => {
                  let out = &context.store.resource_to_ad3(&url, None).unwrap();
                  println!("{}", out);
              }
              None => {
                  pretty_print_resource(&url, &context.store).unwrap();
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
              None => println!("{:?}", &atom.native_value),
          },
      },
      Err(e) => {
          eprintln!("{}", e);
      }
  }
}
