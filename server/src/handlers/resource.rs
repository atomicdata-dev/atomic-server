use serde::Serialize;
use std::path::Path;
use tera::{Context as TeraCtx};
use atomic_lib::store::{self, Property};
use atomic_lib::serialize;
use actix_web::{web, http, HttpRequest, HttpResponse};
use crate::AppState;
use crate::errors::BetterResult;
use crate::log;
use std::sync::Mutex;

enum ContentType {
  JSON,
  HTML,
  AD3,
}

pub async fn get_resource(
  _id: web::Path<String>,
  data: web::Data<Mutex<AppState>>,
  req: HttpRequest,
) -> BetterResult<HttpResponse> {
  let path = Path::new(_id.as_str());
  let id = path.file_stem().unwrap().to_str().unwrap();
  let content_type: ContentType = match path.extension() {
      Some(extension) => {
          match extension.to_str().unwrap() {
          "ad3" => ContentType::AD3,
          "json" => ContentType::JSON,
          "html" => ContentType::HTML,
          _ => ContentType::HTML,
          }
      }
      None => ContentType::HTML,
  } ;
  log::info(&format!("{:?}", id));
  log::info(&format!("method: {:?}", req.method()));
  let context = data.lock().unwrap();
  // This is how locally items are stored (which don't know their full subject URL) in Atomic Data
  let subject = format!("_:{}", id);
  let mut builder = HttpResponse::Ok();
  match content_type {
      ContentType::JSON => {
          builder.set(
              http::header::ContentType::json()
          );
          let body = serialize::resource_to_json(&subject, &context.store, 1)?;
          Ok(builder.body(body))
      }
      ContentType::HTML => {
          builder.set(
              http::header::ContentType::html()
          );
          let mut tera_context = TeraCtx::new();
          let resource = context.store.get(&subject).ok_or("Resource not found")?;
          let mut propvals: Vec<PropVal> = Vec::new();

          #[derive(Serialize)]
          struct PropVal {
              property: Property,
              value: String,
          }
          for (property, value) in resource.iter() {
              let fullprop =  store::get_property(property, &context.store)?;
              let propval = PropVal {
                  property: fullprop,
                  value: value.into(),
              };
              println!("{:?}", propval.property.shortname);
              propvals.push(propval);
          }
          tera_context.insert("resource", &propvals);
          let body = context
              .tera
              .render("resource.html", &tera_context)
              .unwrap();
          Ok(builder.body(body))
      }
      ContentType::AD3 => {
          builder.set(
              http::header::ContentType::html()
          );
          let body = serialize::resource_to_ad3(&subject, &context.store, Some(&context.domain))?;
          Ok(builder.body(body))
      }
  }
}
