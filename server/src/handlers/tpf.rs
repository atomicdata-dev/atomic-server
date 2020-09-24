use crate::render::atom::RenderAtom;
use crate::{appstate::AppState, content_types::get_accept};
use crate::{content_types::ContentType, errors::BetterResult, helpers::empty_to_nothing};
use actix_web::{http, web, HttpResponse};
use atomic_lib::Storelike;
use serde::Deserialize;
use std::sync::Mutex;
use tera::Context as TeraCtx;

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
    let content_type = get_accept(req);
    let subject = empty_to_nothing(query.subject.clone());
    let property = empty_to_nothing(query.property.clone());
    let value = empty_to_nothing(query.value.clone());
    let atoms = store
        .tpf(subject.as_deref(), property.as_deref(), value.as_deref())?;
    log::info!("{:?}", query);
    match content_type {
        ContentType::JSON | ContentType::JSONLD => {
            builder.header("Content-Type", content_type.to_mime());
            // TODO
            log::error!("Not implemented");
            Ok(builder.body("Not implemented"))
        }
        ContentType::HTML => {
            let mut renderedatoms: Vec<RenderAtom> = Vec::new();

            for atom in atoms {
                renderedatoms.push(RenderAtom::from_atom(atom, store)?);
            }

            builder.set(http::header::ContentType::html());
            let mut tera_context = TeraCtx::new();
            tera_context.insert("atoms", &renderedatoms);
            tera_context.insert("subject", &subject);
            tera_context.insert("property", &property);
            tera_context.insert("value", &value);
            let body = context.tera.render("tpf.html", &tera_context)?;
            Ok(builder.body(body))
        }
        ContentType::AD3 => {
            builder.header("Content-Type", content_type.to_mime());
            let ad3_string = atomic_lib::serialize::serialize_atoms_to_ad3(atoms)?;
            Ok(builder.body(ad3_string))
        }
        ContentType::TURTLE | ContentType::NT => {
            builder.header("Content-Type", content_type.to_mime());
            let bod_string = atomic_lib::serialize::atoms_to_ntriples(atoms, store)?;
            Ok(builder.body(bod_string))
        }
    }
}
