use crate::{appstate::AppState, content_types::get_accept};
use crate::{content_types::ContentType, errors::AtomicServerResult, helpers::empty_to_nothing};
use actix_web::{web, HttpResponse};
use atomic_lib::{Storelike, Value};
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Mutex;

#[derive(Deserialize, Debug)]
pub struct TpfQuery {
    pub subject: Option<String>,
    pub property: Option<String>,
    pub value: Option<String>,
}

/// Triple Pattern Fragment handler.
/// Reads optional 'subject' 'property' 'value' from query params, searches the store, return triples.
#[tracing::instrument(skip(data, req))]
pub async fn tpf(
    data: web::Data<Mutex<AppState>>,
    req: actix_web::HttpRequest,
    query: web::Query<TpfQuery>,
) -> AtomicServerResult<HttpResponse> {
    let appstate = data.lock().unwrap();
    let store = &appstate.store;

    if !appstate.config.opts.public_mode {
        return Err("/tpf endpoint is only available on public mode".into());
    }
    // This is how locally items are stored (which don't know their full subject URL) in Atomic Data
    let mut builder = HttpResponse::Ok();
    let content_type = get_accept(req.headers());
    let subject = empty_to_nothing(query.subject.clone());
    let property = empty_to_nothing(query.property.clone());
    let value = query.value.clone().map(Value::String);
    let atoms = store.tpf(
        subject.as_deref(),
        property.as_deref(),
        value.as_ref(),
        true,
    )?;
    tracing::info!("TPF query: {:?}", query);
    builder.insert_header(("Content-Type", content_type.to_mime()));
    match content_type {
        ContentType::JsonAd => {
            let mut resources = vec![];
            // Only search each subject once, to avoid duplicate entries
            let mut subjects = HashSet::new();
            for atom in atoms {
                subjects.insert(atom.subject.clone());
            }
            for subject in subjects {
                resources.push(store.get_resource(&subject)?);
            }
            Ok(builder.body(atomic_lib::serialize::resources_to_json_ad(&resources)?))
        }
        ContentType::Json | ContentType::Html | ContentType::JsonLd => {
            // TODO
            tracing::error!("This Content-Type is not implemented");
            Ok(builder.body("This Content-Type is not implemented"))
        }
        ContentType::Turtle | ContentType::NTriples => {
            let bod_string = atomic_lib::serialize::atoms_to_ntriples(atoms, store)?;
            Ok(builder.body(bod_string))
        }
    }
}
