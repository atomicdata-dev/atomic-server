use serde::{Deserialize};
use tera::{Context as TeraCtx};
use actix_web::{web, http, HttpResponse};
use crate::appstate::AppState;
use crate::render::atom::RenderAtom;
use crate::{content_types::ContentType, errors::BetterResult};
use atomic_lib::Storelike;
use log;
use std::sync::Mutex;

#[derive(Deserialize, Debug)]
pub struct TPFQuery {
   subject: Option<String>,
   property: Option<String>,
   value: Option<String>,
}

pub async fn tpf(
  data: web::Data<Mutex<AppState>>,
  query: web::Query<TPFQuery>,
) -> BetterResult<HttpResponse> {
  let context = data.lock().unwrap();
  // This is how locally items are stored (which don't know their full subject URL) in Atomic Data
  let mut builder = HttpResponse::Ok();
  let content_type = ContentType::HTML;
  let subject = empty_to_nothing(query.subject.clone());
  let property = empty_to_nothing(query.property.clone());
  let value = empty_to_nothing(query.value.clone());
  let atoms = context.store.tpf(subject.clone(), property.clone(), value.clone())?;
  log::info!("{:?}", query);
  match content_type {
      ContentType::JSON => {
          builder.set(
              http::header::ContentType::json()
          );
          Ok(builder.body(""))
      }
      ContentType::HTML => {
          let mut renderedatoms: Vec<RenderAtom> = Vec::new();

          for atom in atoms {
            renderedatoms.push(RenderAtom::from_atom(&atom, &context.store)?);
          }

          builder.set(
              http::header::ContentType::html()
          );
          let mut tera_context = TeraCtx::new();
          // Use the value_to_html helper here
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
          // let plainatoms = atoms.iter().map(|atom| rich_to_plain(atom)).collect();
          let ad3_string = atomic_lib::serialize::serialize_atoms_to_ad3(atoms)?;
          Ok(builder.body(ad3_string))
      }
  }
}

fn empty_to_nothing(string: Option<String>) -> Option<String> {
  match string.as_ref() {
      Some(st) => {
        if st.len() == 0 {
          return None
        } else {
          return string
        }
      }
      None => return None
  }
}
