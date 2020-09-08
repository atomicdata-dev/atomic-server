
use crate::errors::AtomicResult;
use crate::{Storelike, Atom, urls};

pub fn serialize_json_array(items: &[String]) -> AtomicResult<String> {
    let string = serde_json::to_string(items)?;
    Ok(string)
}

pub fn serialize_json_array_owned(items: &[String]) -> AtomicResult<String> {
    let string = serde_json::to_string(items)?;
    Ok(string)
}

/// Serializes Atoms to .ad3.
/// It is a newline-delimited JSON file (ndjson), where each line is a JSON Array with three string values.
pub fn serialize_atoms_to_ad3(atoms: Vec<Atom>) -> AtomicResult<String> {
    let mut string = String::new();
    for atom in atoms {
        let mut ad3_atom = serde_json::to_string(&vec![&atom.subject, &atom.property, &atom.value])?;
        ad3_atom.push_str("\n");
        string.push_str(&*ad3_atom);
    }
    Ok(string)
}

/// N-Triples serialization.
/// Note that N-Triples is also valid Turtle, N3 and Notation3.
/// This is an expensive function, as every atom's datatype has to be fetched.
pub fn serialize_atoms_to_n_triples(atoms: Vec<Atom>, store: &dyn Storelike) -> AtomicResult<String> {
    eprintln!("CAUTION: N-Triples serialization is not implemented correctly, values are not escaped correctly.");
    if atoms.is_empty() {
        return Err("No atoms to serialize".into())
    }
    let mut string = String::new();
    for atom in atoms {
        let datatype = store.get_property(&atom.property)?.data_type;

        // TODO: Implement this!
        let esc_value = escape_turtle_value(&atom.value);

        // e.g. "That Seventies Show"^^<http://www.w3.org/2001/XMLSchema#string>
        let dtstring = |dt: &str| {
            format!("\"{}\"^^<{}>", esc_value, dt)
        };

        let value = match datatype {
            crate::values::DataType::AtomicUrl => format!("<{}>", esc_value),
            crate::values::DataType::Date => dtstring(urls::DATE),
            crate::values::DataType::Integer => dtstring(urls::INTEGER),
            crate::values::DataType::Markdown => dtstring(urls::MARKDOWN),
            crate::values::DataType::ResourceArray => dtstring(urls::RESOURCE_ARRAY),
            crate::values::DataType::Slug => dtstring(urls::SLUG),
            crate::values::DataType::String => format!("\"{}\"", esc_value),
            crate::values::DataType::Timestamp => dtstring(urls::TIMESTAMP),
            crate::values::DataType::Unsupported(uns) => dtstring(&uns),
        };
        let ad3_atom = format!("<{}> <{}> {} . \n", atom.subject, atom.property, value);
        string.push_str(&*ad3_atom);
    }
    Ok(string)
}

/// SHOULD escape turtle value strings
/// Probably will need to use an external library...
// US-ASCII
// https://www.w3.org/TR/rdf-testcases/#ntriples
fn escape_turtle_value (string: &str) -> &str {
    string
}

pub const SERIALIZE_OPTIONS: [&str; 5] = ["pretty", "json", "jsonld", "ad3", "nt"];

/// Should list all the supported serialization formats
pub enum Format {
    JSON,
    JSONLD,
    AD3,
    NT,
    PRETTY,
}
