use super::atom::value_to_html;
use crate::errors::BetterResult;
use atomic_lib::{storelike::Property, Storelike};
use serde::Serialize;

/// Useful for rendering Atomic Data
#[derive(Serialize)]
pub struct HTMLAtom {
    pub property: Property,
    pub value: String,
    pub value_html: String,
    pub subject: String,
}

/// Creates a vector of HTML Atoms, which have easy to print HTML values.
/// Useful because Tera can then iterate over these.
pub fn propvals_to_html(
    propvals: &atomic_lib::resources::PropVals,
    store: &dyn Storelike,
    subject: String,
) -> BetterResult<Vec<HTMLAtom>> {
    let mut htmlatoms: Vec<HTMLAtom> = Vec::new();

    for (property, value) in propvals.iter() {
        let fullprop = store.get_property(property)?;
        htmlatoms.push(HTMLAtom {
            property: fullprop,
            value: value.to_string(),
            value_html: value_to_html(&value),
            subject: subject.clone(),
        });
    }
    Ok(htmlatoms)
}
