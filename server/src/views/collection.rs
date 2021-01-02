use crate::{
    appstate::AppState,
    errors::BetterResult,
    render::propvals::{propvals_to_html_map, HTMLAtom, HTMLAtomProp},
};
use atomic_lib::{schema::Property, Resource, Storelike};
use serde::Serialize;
use std::{collections::HashMap, sync::MutexGuard};

/// This should be used in Tera for rendering and other data that should be available in the template.
#[derive(Serialize)]
struct CollectionTable {
    header: Vec<Property>,
    members: Vec<Vec<HTMLAtomProp>>,
}

pub fn render_collection(
    resource: &Resource,
    context: &MutexGuard<AppState>,
) -> BetterResult<String> {
    let mut tera_context = tera::Context::new();
    let store = &context.store;
    let members = resource
        .get(atomic_lib::urls::COLLECTION_MEMBERS)?
        .to_vec()?;
    // The header is a vector of properties, sorted by how important it is.
    // Maybe we could use this vector to store 'ordered by' settings
    let mut header: Vec<Property> = Vec::new();
    // In the view, we use the shortnames of the Properties in the Header to find the fields in resources.
    // This works because Tera supports HashMaps.
    let mut resources: Vec<HashMap<String, HTMLAtom>> = Vec::new();
    for member in members {
        let resource = store.get_resource(member)?;
        let propvals = propvals_to_html_map(
            &resource.get_propvals(),
            store,
            resource.get_subject().clone(),
        )?;
        resources.push(propvals);

        let classes = resource.get_classes(store)?;
        // Add every new property to the header
        // Currently only adds props from the Class, not randomly used properties.
        for class in classes {
            for prop in class.requires {
                if !header.contains(&prop) {
                    header.push(prop);
                }
            }
            for prop in class.recommends {
                if !header.contains(&prop) {
                    header.push(prop);
                }
            }
        }
    }

    tera_context.insert("header", &header);
    tera_context.insert("resources", &resources);
    let body = context.tera.render("collection.html", &tera_context)?;

    Ok(body)
}
