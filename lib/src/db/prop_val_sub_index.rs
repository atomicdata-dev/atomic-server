//! Index sorted by {Property}-{Value}-{Subject}.
use crate::{atoms::IndexAtom, errors::AtomicResult, storelike::Storelike, Db, Value};

use super::{
    query_index::{
        property_from_key_part, property_key_part, sort_part, IndexIterator, SEPARATION_BIT,
    },
    trees::{Method, Operation, Transaction, Tree},
};

/// Finds all Atoms for a given {property}-{value} tuple.
pub fn find_in_prop_val_sub_index(store: &Db, prop: &str, val: Option<&Value>) -> IndexIterator {
    let mut prefix: Vec<u8> = [&property_key_part(prop)[..], &[SEPARATION_BIT]].concat();
    if let Some(value) = val {
        prefix.extend(value.to_sortable_string().as_bytes());
        prefix.extend([SEPARATION_BIT]);
    }
    // Subjects are stored as their raw URL form in the index key. On read we
    // must re-normalize against the server's base_domain so that e.g.
    // `https://localhost/x` becomes `Subject::Internal { internal:/x }` — the
    // later `is_local()` filter in `query_basic` rejects `Subject::External`,
    // which would drop every hit from a query against a localhost server.
    let base_domain = store.get_base_domain();
    Box::new(
        store
            .kv
            .scan_prefix(Tree::PropValSub, &prefix)
            .map(move |kv| {
                let (key, _value) = kv?;
                key_to_index_atom(&key, base_domain.as_deref())
            }),
    )
}

pub fn add_atom_to_prop_val_sub_index(
    index_atom: &IndexAtom,
    transaction: &mut Transaction,
) -> AtomicResult<()> {
    transaction.push(Operation {
        key: propvalsub_key(index_atom),
        val: Some(b"".to_vec()),
        tree: Tree::PropValSub,
        method: Method::Insert,
    });
    Ok(())
}

/// Constructs the Key for the prop_val_sub_index.
///
/// An atom's sort value is its reference value, so the key leaves the sort
/// part empty then instead of writing a long URL or text twice
/// ([`sort_part`]). Keys from before that kept it, and are still read.
pub fn propvalsub_key(atom: &IndexAtom) -> Vec<u8> {
    key_with_sort_part(&property_key_part(&atom.property), atom, sort_part(atom))
}

/// The key as stores before the sort part was left out wrote it. Removing an
/// atom deletes this form too, so rows from an older store go with it.
pub fn propvalsub_legacy_key(atom: &IndexAtom) -> Vec<u8> {
    key_with_sort_part(atom.property.as_bytes(), atom, atom.sort_value.as_bytes())
}

fn key_with_sort_part(property: &[u8], atom: &IndexAtom, sort: &[u8]) -> Vec<u8> {
    [
        property,
        &[SEPARATION_BIT],
        atom.ref_value.as_bytes(),
        &[SEPARATION_BIT],
        sort,
        &[SEPARATION_BIT],
        atom.subject.as_str().as_bytes(),
    ]
    .concat()
}

/// Parses a Value index key string, converts it into an atom.
/// Note that the Value of the atom will always be a single AtomicURL here.
fn key_to_index_atom(key: &[u8], base_domain: Option<&str>) -> AtomicResult<IndexAtom> {
    let mut parts = key.split(|b| b == &SEPARATION_BIT);
    let prop = property_from_key_part(parts.next().ok_or("Invalid key for prop_val_sub_index")?)?;
    let ref_val = std::str::from_utf8(parts.next().ok_or("Invalid key for prop_val_sub_index")?)
        .map_err(|_| "Can't parse ref_val into string")?;
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
        subject: crate::Subject::from_raw(sub, base_domain),
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
        let key = propvalsub_key(&atom);
        let atom2 = key_to_index_atom(&key, None).unwrap();
        assert_eq!(atom, atom2);
    }

    #[test]
    fn sort_value_equal_to_the_reference_is_not_written_twice() {
        let atom = IndexAtom {
            property: "http://example.com/prop".into(),
            ref_value: "http://example.com/a/long/value".into(),
            sort_value: "http://example.com/a/long/value".into(),
            subject: "http://example.com/subj".into(),
        };
        let key = propvalsub_key(&atom);
        assert!(key.len() < propvalsub_legacy_key(&atom).len());
        assert_eq!(key_to_index_atom(&key, None).unwrap(), atom);
        assert_eq!(
            key_to_index_atom(&propvalsub_legacy_key(&atom), None).unwrap(),
            atom
        );
        // Both forms sit under the same `{property}-{value}-` prefix a lookup scans.
        let prefix = [
            atom.property.as_bytes(),
            &[SEPARATION_BIT],
            atom.ref_value.as_bytes(),
            &[SEPARATION_BIT],
        ]
        .concat();
        assert!(key.starts_with(&prefix) && propvalsub_legacy_key(&atom).starts_with(&prefix));
    }
}
