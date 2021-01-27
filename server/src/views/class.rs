use crate::{appstate::AppState, errors::BetterResult, render::propvals::{HTMLAtomProp, propvals_to_html_vec}};
use atomic_lib::{Resource, Storelike, schema::Property};
use serde::Serialize;
use std::{sync::MutexGuard};

/// This should be used in Tera for rendering and other data that should be available in the template.
#[derive(Serialize)]
struct CollectionTable {
    header: Vec<Property>,
    members: Vec<Vec<HTMLAtomProp>>,
}

pub fn render_class(
    resource: &Resource,
    context: &MutexGuard<AppState>,
) -> BetterResult<String> {
    let mut tera_context = tera::Context::new();
    let class = atomic_lib::schema::Class::from_resource(resource)?;
    let propvals = propvals_to_html_vec(
        &resource.get_propvals(),
        &context.store,
        resource.get_subject().clone(),
    )?;
    let mut requires = Vec::new();
    for propurl in class.clone().recommends {
        requires.push(context.store.get_property(&propurl)?);
    }
    let mut recommends = Vec::new();
    for propurl in class.clone().requires {
        recommends.push(context.store.get_property(&propurl)?);
    }

    tera_context.insert("class", &class);
    tera_context.insert("propvals", &propvals);
    tera_context.insert("requires", &requires);
    tera_context.insert("recommends", &recommends);

    let body = context.tera.render("class.html", &tera_context)?;

    Ok(body)
}
