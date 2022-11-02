//! The smallest units of data, consisting of a Subject, a Property and a Value

use crate::{
    errors::AtomicResult,
    values::{ReferenceString, SortableValue, Value},
};

/// The Atom is the smallest meaningful piece of data.
/// It describes how one value relates to a subject.
/// A [Resource] can be converted into a bunch of Atoms.
#[derive(Clone, Debug)]
pub struct Atom {
    /// The URL where the resource is located
    pub subject: String,
    pub property: String,
    pub value: Value,
}

impl Atom {
    pub fn new(subject: String, property: String, value: Value) -> Self {
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
        let sort_value = self.value.to_sortable_string();
        let index_atoms = match &self.value.to_reference_index_strings() {
            Some(v) => v,
            None => return vec![],
        }
        .iter()
        .map(|v| IndexAtom {
            ref_value: v.into(),
            sort_value: sort_value.clone(),
            subject: self.subject.clone(),
            property: self.property.clone(),
        })
        .collect();
        index_atoms
    }
}

/// Differs from a regular [Atom], since the value here is always a string,
/// and in the case of ResourceArrays, only a _single_ subject is used for each atom.
/// One IndexAtom for every member of the ResourceArray is created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexAtom {
    pub subject: String,
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
