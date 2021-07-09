use crate::{appstate::AppState, content_types::get_accept};
use crate::{content_types::ContentType, errors::BetterResult, helpers::empty_to_nothing};
use actix_web::{web, HttpResponse};
use atomic_lib::Storelike;
use serde::Deserialize;
use std::sync::Mutex;

#[derive(Deserialize, Debug)]
pub struct TPFQuery {
    pub subject: Option<String>,
    pub property: Option<String>,
    pub value: Option<String>,
}

/// Triple Pattern Fragment handler.
/// Reads optional 'subject' 'property' 'value' from query params, searches the store, return triples.
pub async fn tpf(
    data: web::Data<Mutex<AppState>>,
    req: actix_web::HttpRequest,
    query: web::Query<TPFQuery>,
) -> BetterResult<HttpResponse> {
    let mut context = data.lock().unwrap();
    let store = &mut context.store;
    // This is how locally items are stored (which don't know their full subject URL) in Atomic Data
    let mut builder = HttpResponse::Ok();
    let content_type = get_accept(req.headers());
    let subject = empty_to_nothing(query.subject.clone());
    let property = empty_to_nothing(query.property.clone());
    let value = empty_to_nothing(query.value.clone());
    let atoms = store
        .tpf(subject.as_deref(), property.as_deref(), value.as_deref(), true)?;
    log::info!("TPF query: {:?}", query);
    match content_type {
        ContentType::JSON | ContentType::HTML | ContentType::JSONLD | ContentType::JSONAD => {
            builder.header("Content-Type", content_type.to_mime());
            // TODO
            log::error!("Not implemented");
            Ok(builder.body("Not implemented"))
        }
        ContentType::TURTLE | ContentType::NT => {
            builder.header("Content-Type", content_type.to_mime());
            let bod_string = atomic_lib::serialize::atoms_to_ntriples(atoms, store)?;
            Ok(builder.body(bod_string))
        }
    }
}
