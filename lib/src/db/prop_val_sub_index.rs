//! Index sorted by {Property}-{Value}-{Subject}.

use tracing::instrument;

use crate::{atoms::IndexAtom, errors::AtomicResult, Db, Value};

use super::query_index::{IndexIterator, SEPARATION_BIT};

/// Finds all Atoms for a given {property}-{value} tuple.
pub fn find_in_prop_val_sub_index(store: &Db, prop: &str, val: Option<&Value>) -> IndexIterator {
    let mut prefix: Vec<u8> = [prop.as_bytes(), &[SEPARATION_BIT]].concat();
    if let Some(value) = val {
        prefix.extend(value.to_sortable_string().as_bytes());
        prefix.extend([SEPARATION_BIT]);
    }
    Box::new(store.prop_val_sub_index.scan_prefix(prefix).map(|kv| {
        let (key, _value) = kv?;
        key_to_index_atom(&key)
    }))
}

#[instrument(skip(store))]
pub fn add_atom_to_prop_val_sub_index(index_atom: &IndexAtom, store: &Db) -> AtomicResult<()> {
    let _existing = store
        .prop_val_sub_index
        .insert(key_from_atom(index_atom), b"");
    Ok(())
}

#[instrument(skip(store))]
pub fn remove_atom_from_prop_val_sub_index(index_atom: &IndexAtom, store: &Db) -> AtomicResult<()> {
    let _existing = store.prop_val_sub_index.remove(key_from_atom(index_atom));
    Ok(())
}

/// Constructs the Key for the prop_val_sub_index.
fn key_from_atom(atom: &IndexAtom) -> Vec<u8> {
    [
        atom.property.as_bytes(),
        &[SEPARATION_BIT],
        atom.ref_value.as_bytes(),
        &[SEPARATION_BIT],
        atom.sort_value.as_bytes(),
        &[SEPARATION_BIT],
        atom.subject.as_bytes(),
    ]
    .concat()
}

/// Parses a Value index key string, converts it into an atom.
/// Note that the Value of the atom will always be a single AtomicURL here.
fn key_to_index_atom(key: &[u8]) -> AtomicResult<IndexAtom> {
    let mut parts = key.split(|b| b == &SEPARATION_BIT);
    let prop = std::str::from_utf8(parts.next().ok_or("Invalid key for prop_val_sub_index")?)
        .map_err(|_| "Can't parse prop into string")?;
    let ref_val = std::str::from_utf8(parts.next().ok_or("Invalid key for prop_val_sub_index")?)
        .map_err(|_| "Can't parse ref_val into string")?;
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
