//! Index sorted by {Value}-{Property}-{Subject}.
use crate::{atoms::IndexAtom, errors::AtomicResult, Db, Value};
use tracing::instrument;

use super::query_index::{IndexIterator, SEPARATION_BIT};

#[instrument(skip(store))]
pub fn add_atom_to_reference_index(index_atom: &IndexAtom, store: &Db) -> AtomicResult<()> {
    let _existing = store
        .reference_index
        .insert(key_from_atom(index_atom), b"")?;
    Ok(())
}

#[instrument(skip(store))]
pub fn remove_atom_from_reference_index(index_atom: &IndexAtom, store: &Db) -> AtomicResult<()> {
    store.reference_index.remove(key_from_atom(index_atom))?;
    Ok(())
}

/// Constructs the Key for the prop_val_sub_index.
fn key_from_atom(atom: &IndexAtom) -> Vec<u8> {
    [
        atom.ref_value.as_bytes(),
        &[SEPARATION_BIT],
        atom.property.as_bytes(),
        &[SEPARATION_BIT],
        atom.sort_value.as_bytes(),
        &[SEPARATION_BIT],
        atom.subject.as_bytes(),
    ]
    .concat()
}

/// Finds all Atoms for a given {value}.
pub fn find_in_val_prop_sub_index(store: &Db, val: &Value, prop: Option<&str>) -> IndexIterator {
    let ref_index = val.to_reference_index_strings();
    let value_key = if let Some(v) = ref_index {
        if let Some(index_str) = v.first() {
            index_str.to_string()
        } else {
            return Box::new(std::iter::empty());
        }
    } else {
        return Box::new(::std::iter::empty());
    };
    let mut prefix: Vec<u8> = [value_key.as_bytes(), &[SEPARATION_BIT]].concat();
    if let Some(prop) = prop {
        prefix.extend(prop.as_bytes());
        prefix.extend([SEPARATION_BIT]);
    }
    Box::new(store.reference_index.scan_prefix(prefix).map(|kv| {
        let (key, _value) = kv?;
        key_to_index_atom(&key)
    }))
}

/// Parses a Value index key string, converts it into an atom.
/// Note that the Value of the atom will always be a single AtomicURL here.
fn key_to_index_atom(key: &[u8]) -> AtomicResult<IndexAtom> {
    let mut parts = key.split(|b| b == &SEPARATION_BIT);
    let ref_val = std::str::from_utf8(parts.next().ok_or("Invalid key for prop_val_sub_index")?)
        .map_err(|_| "Can't parse ref_val into string")?;
    let prop = std::str::from_utf8(parts.next().ok_or("Invalid key for prop_val_sub_index")?)
        .map_err(|_| "Can't parse prop into string")?;
    let sort_val = std::str::from_utf8(parts.next().ok_or("Invalid key for prop_val_sub_index")?)
        .map_err(|_| "Can't parse sort_val into string")?;
    let sub = std::str::from_utf8(parts.next().ok_or("Invalid key for prop_val_sub_index")?)
        .map_err(|_| "Can't parse subject into string")?;
    Ok(IndexAtom {
        property: prop.into(),
        ref_value: ref_val.into(),
        sort_value: sort_val.into(),
        subject: sub.into(),
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn round_trip() {
        let atom = IndexAtom {
            property: "http://example.com/prop".into(),
            ref_value: "http://example.com/val \n hello \n".into(),
            sort_value: "2".into(),
            subject: "http://example.com/subj".into(),
        };
        let key = key_from_atom(&atom);
        let atom2 = key_to_index_atom(&key).unwrap();
        assert_eq!(atom, atom2);
    }
}
