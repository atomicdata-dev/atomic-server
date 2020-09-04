use serde_json;
use crate::errors::AtomicResult;
use crate::Atom;

pub fn deserialize_json_array(string: &String) -> AtomicResult<Vec<String>> {
    let vector: Vec<String> = serde_json::from_str(string)?;
    return Ok(vector)
}

pub fn serialize_json_array(items: &Vec<String>) -> AtomicResult<String> {
    let string = serde_json::to_string(items).expect("Can't serialize to string");
    return Ok(string);
}

pub fn serialize_atoms_to_ad3(atoms: Vec<Atom>) -> AtomicResult<String> {
    let mut string = String::new();
    for atom in atoms {
        let mut ad3_atom = serde_json::to_string(&vec![&atom.subject, &atom.property, &atom.value])
            .expect("Can't serialize");
        ad3_atom.push_str("\n");
        &string.push_str(&*ad3_atom);
    }
    return Ok(string);
}

// Should list all the supported serialization formats
pub enum SerialializationFormats {
    JSON,
    JSONLD,
    AD3,
}
