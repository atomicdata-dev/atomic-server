//! The smallest units of data, consisting of a Subject, a Property and a Value

use crate::{
    errors::AtomicResult,
    values::{ReferenceString, SortableValue, Value},
    Subject,
};

/// The Atom is the smallest meaningful piece of data.
/// It describes how one value relates to a subject.
/// A [Resource] can be converted into a bunch of Atoms.
#[derive(Clone, Debug)]
pub struct Atom {
    /// The URL where the resource is located
    pub subject: Subject,
    pub property: String,
    pub value: Value,
}

impl Atom {
    pub fn new(subject: Subject, property: String, value: Value) -> Self {
        Atom {
            subject,
            property,
            value,
        }
    }

    /// If the Atom's Value is an Array, this will try to convert it into a set of Subjects.
    /// Used for indexing.
    pub fn values_to_subjects(&self) -> AtomicResult<Vec<String>> {
        let base_path = format!("{} {}", self.subject, self.property);
        self.value.to_subjects(Some(base_path))
    }

    /// Converts one Atom to a series of stringified values that can be indexed.
    pub fn to_indexable_atoms(&self) -> Vec<IndexAtom> {
        if self.property == crate::urls::GENESIS {
            return Vec::new();
        }
        self.to_stored_index_atoms()
    }

    /// Every index atom the atom could ever have been stored under, including
    /// the ones [`Self::to_indexable_atoms`] no longer writes. Removal uses
    /// this so rows an older store holds are deleted with the resource.
    pub(crate) fn to_stored_index_atoms(&self) -> Vec<IndexAtom> {
        // `to_indexable_atoms` leaves out the genesis certificate: a ~340-byte
        // blob only ever read off the resource, which put an ~800-byte key in
        // both atom indexes for every resource (about 1.6 KB of ~12 KB).
        // Using sort_value causes issues but we really need to look at how to do this properly.
        // let sort_value = self.value.to_sortable_string();
        let index_atoms: Vec<IndexAtom> = match &self.value.to_reference_index_strings() {
            Some(v) => {
                tracing::trace!(
                    "to_indexable_atoms: found {} reference strings for property {}",
                    v.len(),
                    self.property
                );
                v.iter()
                    .map(|v| IndexAtom {
                        ref_value: v.into(),
                        sort_value: v.into(),
                        subject: self.subject.clone(),
                        property: self.property.clone(),
                    })
                    .collect()
            }
            None => {
                tracing::trace!(
                    "to_indexable_atoms: no reference strings for property {}",
                    self.property
                );
                vec![]
            }
        };
        index_atoms
    }
}

/// Differs from a regular [Atom], since the value here is always a string,
/// and in the case of ResourceArrays, only a _single_ subject is used for each atom.
/// One IndexAtom for every member of the ResourceArray is created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexAtom {
    pub subject: Subject,
    pub property: String,
    pub ref_value: ReferenceString,
    pub sort_value: SortableValue,
}

impl std::fmt::Display for Atom {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.write_str(&format!(
            "<{}> <{}> '{}'",
            self.subject, self.property, self.value
        ))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_certificate_is_not_indexed() {
        let genesis = Atom::new(
            "did:ad:abc".into(),
            crate::urls::GENESIS.into(),
            Value::String("AQBKG29d".into()),
        );
        assert!(genesis.to_indexable_atoms().is_empty());
        let name = Atom::new(
            "did:ad:abc".into(),
            crate::urls::NAME.into(),
            Value::String("A title".into()),
        );
        assert_eq!(name.to_indexable_atoms().len(), 1);
    }
}
