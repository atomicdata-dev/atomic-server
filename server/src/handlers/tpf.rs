use serde::{Deserialize};
use tera::{Context as TeraCtx};
use actix_web::{web, http, HttpResponse};
use crate::{appstate::AppState, content_types::get_accept};
use crate::render::atom::RenderAtom;
use crate::{content_types::ContentType, errors::BetterResult, helpers::empty_to_nothing};
use atomic_lib::Storelike;
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
  let context = data.lock().unwrap();
  // This is how locally items are stored (which don't know their full subject URL) in Atomic Data
  let mut builder = HttpResponse::Ok();
  let content_type = get_accept(req);
  let subject = empty_to_nothing(query.subject.clone());
  let property = empty_to_nothing(query.property.clone());
  let value = empty_to_nothing(query.value.clone());
  let atoms = context.store.tpf(subject.as_deref(), property.as_deref(), value.as_deref())?;
  log::info!("{:?}", query);
  match content_type {
      ContentType::JSON | ContentType::JSONLD => {
          builder.set(
              http::header::ContentType::json()
          );
          // TODO
          log::error!("Not implemented");
          Ok(builder.body("Not implemented"))
      }
      ContentType::HTML => {
          let mut renderedatoms: Vec<RenderAtom> = Vec::new();

          for atom in atoms {
            renderedatoms.push(RenderAtom::from_atom(atom, &context.store)?);
          }

          builder.set(
              http::header::ContentType::html()
          );
          let mut tera_context = TeraCtx::new();
          tera_context.insert("atoms", &renderedatoms);
          tera_context.insert("subject", &subject);
          tera_context.insert("property", &property);
          tera_context.insert("value", &value);
          let body = context
              .tera
              .render("tpf.html", &tera_context)
              .unwrap();
          Ok(builder.body(body))
      }
      ContentType::AD3 => {
          builder.set(
              http::header::ContentType::html()
          );
          let ad3_string = atomic_lib::serialize::serialize_atoms_to_ad3(atoms)?;
          Ok(builder.body(ad3_string))
      }
  }
}
