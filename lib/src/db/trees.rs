use crate::atoms::IndexAtom;

use super::{
    migrations::{REFERENCE_INDEX_CURRENT, RESOURCE_TREE_CURRENT},
    prop_val_sub_index::propvalsub_key,
    val_prop_sub_index::valpropsub_key,
};

#[derive(Debug)]
pub enum Tree {
    /// Full resources, Key: Subject, Value: [Resource](crate::Resource)
    Resources,
    /// Stores the members of Collections, easily sortable.
    QueryMembers,
    /// A list of all the Collections currently being used. Is used to update `query_index`.
    WatchedQueries,
    /// Index sorted by {Property}-{Value}-{Subject}.
    /// Used for queries where the property is known.
    PropValSub,
    /// Reference index, used for queries where the value (or one of the values, in case of an array) is but the subject is not.
    /// Index sorted by {Value}-{Property}-{Subject}.
    ValPropSub,
}

const RESOURCES: &str = RESOURCE_TREE_CURRENT;
const VALPROPSUB: &str = REFERENCE_INDEX_CURRENT;
const QUERY_MEMBERS: &str = "members_index";
const PROPVALSUB: &str = "prop_val_sub_index";
const QUERIES_WATCHED: &str = "watched_queries";

impl std::fmt::Display for Tree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tree::Resources => f.write_str(RESOURCE_TREE_CURRENT),
            Tree::WatchedQueries => f.write_str(QUERIES_WATCHED),
            Tree::PropValSub => f.write_str(PROPVALSUB),
            Tree::ValPropSub => f.write_str(VALPROPSUB),
            Tree::QueryMembers => f.write_str(QUERY_MEMBERS),
        }
    }
}

// convert Tree into AsRef<[u8]> by using the string above
impl AsRef<[u8]> for Tree {
    fn as_ref(&self) -> &[u8] {
        match self {
            Tree::Resources => RESOURCES.as_bytes(),
            Tree::WatchedQueries => QUERIES_WATCHED.as_bytes(),
            Tree::PropValSub => PROPVALSUB.as_bytes(),
            Tree::ValPropSub => VALPROPSUB.as_bytes(),
            Tree::QueryMembers => QUERY_MEMBERS.as_bytes(),
        }
    }
}

#[derive(Debug)]
pub enum Method {
    Insert,
    Delete,
}

/// A single operation to be executed on the database.
#[derive(Debug)]
pub struct Operation {
    pub tree: Tree,
    pub method: Method,
    pub key: Vec<u8>,
    pub val: Option<Vec<u8>>,
}

impl Operation {
    pub fn remove_atom_from_reference_index(index_atom: &IndexAtom) -> Self {
        Operation {
            tree: Tree::ValPropSub,
            method: Method::Delete,
            key: valpropsub_key(index_atom),
            val: None,
        }
    }
    pub fn remove_atom_from_prop_val_sub_index(index_atom: &IndexAtom) -> Self {
        Operation {
            tree: Tree::PropValSub,
            method: Method::Delete,
            key: propvalsub_key(index_atom),
            val: None,
        }
    }
}

/// A set of [Operation]s that should be executed atomically by the database.
pub type Transaction = Vec<Operation>;
