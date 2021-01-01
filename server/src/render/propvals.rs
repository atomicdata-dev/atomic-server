use std::collections::HashMap;

use super::atom::value_to_html;
use crate::errors::BetterResult;
use atomic_lib::{Storelike, Value, storelike::Property};
use serde::Serialize;

/// Useful for rendering Atomic Data including a label
#[derive(Serialize)]
pub struct HTMLAtomProp {
    pub property: Property,
    pub value: String,
    pub value_html: String,
    pub subject: String,
}

/// Creates a vector of HTML Atoms, which have easy to print HTML values.
/// Useful because Tera can then iterate over these.
pub fn propvals_to_html_vec(
    propvals: &atomic_lib::resources::PropVals,
    store: &impl Storelike,
    subject: String,
) -> BetterResult<Vec<HTMLAtomProp>> {
    let mut htmlatoms: Vec<HTMLAtomProp> = Vec::new();

    for (property, value) in propvals.iter() {
        let fullprop = store.get_property(property)?;
        htmlatoms.push(HTMLAtomProp {
            property: fullprop,
            value: value.to_string(),
            value_html: value_to_html(&value, store),
            subject: subject.clone(),
        });
    }

    // Sort props alphabetically by shortname
    // Always show description first
    htmlatoms.sort_by(|a, b| {
        if b.property.subject == atomic_lib::urls::DESCRIPTION {
            return std::cmp::Ordering::Less
        }
        if b.property.shortname > a.property.shortname {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    });

    Ok(htmlatoms)
}

/// Useful for rendering Atomic Data in tables context.
#[derive(Debug, Serialize)]
pub struct HTMLAtom {
    pub value: String,
    pub value_html: String,
}

/// Creates a vector of HTML Atoms, which have easy to print HTML values.
/// Useful because Tera can then iterate over these.
pub fn propvals_to_html_map(
    propvals: &atomic_lib::resources::PropVals,
    store: &impl Storelike,
    subject: String,
) -> BetterResult<HashMap<String, HTMLAtom>> {
    let mut htmlatoms: HashMap<String, HTMLAtom> = HashMap::new();

    for (property, value) in propvals.iter() {
        let fullprop = store.get_property(property)?;
        // Using the shortname instead of the URL here because of a parsing bug in Tera
        // https://github.com/Keats/tera/issues/590
        htmlatoms.insert(fullprop.shortname,  HTMLAtom {
            value: value.to_string(),
            value_html: value_to_html(&value, store),
        });
    }
    // The subject is often useful
    htmlatoms.insert("subject".into(), HTMLAtom {
        value: subject.clone(),
        value_html: value_to_html(&Value::AtomicUrl(subject), store),
    });
    Ok(htmlatoms)
}
