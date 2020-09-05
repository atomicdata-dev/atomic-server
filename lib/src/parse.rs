use crate::{errors::AtomicResult, Atom};

pub const AD3_MIME: &str = "application/ad3-ndjson";

/// Parses an Atomic Data Triples (.ad3) string and adds the Atoms to the store.
/// Allows comments and empty lines.
pub fn parse_ad3<'a, 'b>(string: &'b String) -> AtomicResult<Vec<Atom>> {
    let mut atoms: Vec<Atom> = Vec::new();
    for line in string.lines() {
        match line.chars().next() {
            // These are comments
            Some('#') => {}
            Some(' ') => {}
            // That's an array, awesome
            Some('[') => {
                let string_vec: Vec<String> =
                    parse_json_array(line).expect(&*format!("Parsing error in {:?}", line));
                if string_vec.len() != 3 {
                    return Err(format!(
                        "Wrong length of array at line {:?}: wrong length of array, should be 3",
                        line
                    )
                    .into());
                }
                let subject = &string_vec[0];
                let property = &string_vec[1];
                let value = &string_vec[2];
                atoms.push(Atom::new(subject, property, value));
            }
            Some(char) => {
                return Err(format!(
                    "AD3 Parsing error at {:?}, cannot start with {}",
                    line, char
                )
                .into())
            }
            None => {}
        };
    }
    return Ok(atoms);
}

pub fn parse_json_array(string: &str) -> AtomicResult<Vec<String>> {
    let vector: Vec<String> = serde_json::from_str(string)?;
    return Ok(vector);
}
