//! Index sorted by {Value}-{Property}-{Subject}.
use crate::{atoms::IndexAtom, errors::AtomicResult, Db, Value};

use super::{
    query_index::{
        property_from_key_part, property_key_part, sort_part, IndexIterator, SEPARATION_BIT,
    },
    trees::{Method, Operation, Transaction, Tree},
};

/// Whether a value can be a reference to another resource. The index is
/// there to answer "what points at X", so a description, a number or a
/// timestamp has no row in it: that was two of the five atoms of a chat
/// message, about 340 bytes, for lookups nothing makes. Decided on the text,
/// not the datatype, so a reference an older document stored as a plain
/// string still counts.
pub fn is_reference(value: &str) -> bool {
    ["http://", "https://", "did:ad:", "atomic:", "internal:"]
        .iter()
        .any(|scheme| value.starts_with(scheme))
        && !value.contains(char::is_whitespace)
}

pub fn add_atom_to_valpropsub_index(
    index_atom: &IndexAtom,
    transaction: &mut Transaction,
) -> AtomicResult<()> {
    if !is_reference(&index_atom.ref_value) {
        return Ok(());
    }
    transaction.push(Operation {
        key: valpropsub_key(index_atom),
        val: Some(b"".to_vec()),
        tree: Tree::ValPropSub,
        method: Method::Insert,
    });
    Ok(())
}

/// Constructs the Key for the val_prop_sub_index. The sort part is left empty
/// when it equals the reference value, as in
/// [`super::prop_val_sub_index::propvalsub_key`].
pub fn valpropsub_key(atom: &IndexAtom) -> Vec<u8> {
    key_with_sort_part(&property_key_part(&atom.property), atom, sort_part(atom))
}

/// The key as stores before the sort part was left out wrote it.
pub fn valpropsub_legacy_key(atom: &IndexAtom) -> Vec<u8> {
    key_with_sort_part(atom.property.as_bytes(), atom, atom.sort_value.as_bytes())
}

fn key_with_sort_part(property: &[u8], atom: &IndexAtom, sort: &[u8]) -> Vec<u8> {
    [
        atom.ref_value.as_bytes(),
        &[SEPARATION_BIT],
        property,
        &[SEPARATION_BIT],
        sort,
        &[SEPARATION_BIT],
        atom.subject.as_str().as_bytes(),
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
        prefix.extend(property_key_part(prop));
        prefix.extend([SEPARATION_BIT]);
    }
    Box::new(store.kv.scan_prefix(Tree::ValPropSub, &prefix).map(|kv| {
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
    let prop = property_from_key_part(parts.next().ok_or("Invalid key for prop_val_sub_index")?)?;
    let sort_val = std::str::from_utf8(parts.next().ok_or("Invalid key for prop_val_sub_index")?)
        .map_err(|_| "Can't parse sort_val into string")?;
    let sub = std::str::from_utf8(parts.next().ok_or("Invalid key for prop_val_sub_index")?)
        .map_err(|_| "Can't parse subject into string")?;
    Ok(IndexAtom {
        property: prop,
        ref_value: ref_val.into(),
        sort_value: if sort_val.is_empty() {
            ref_val
        } else {
            sort_val
        }
        .into(),
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
        let key = valpropsub_key(&atom);
        let atom2 = key_to_index_atom(&key).unwrap();
        assert_eq!(atom, atom2);
    }
}
