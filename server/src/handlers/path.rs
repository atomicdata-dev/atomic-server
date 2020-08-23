use crate::appstate::AppState;
use crate::{content_types::ContentType, errors::BetterResult};
use actix_web::{http, web, HttpResponse};
use atomic_lib::store::Property;
use log;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tera::Context as TeraCtx;

#[derive(Deserialize, Debug)]
pub struct GetQuery {
    path: Option<String>,
}

pub async fn path(
    data: web::Data<Mutex<AppState>>,
    query: web::Query<GetQuery>,
) -> BetterResult<HttpResponse> {
    let path = &query.path.clone().unwrap_or("".into());
    let context = data.lock().unwrap();
    let content_type: ContentType = ContentType::HTML;

    log::info!("path: {:?}", path);
    // This is how locally items are stored (which don't know their full subject URL) in Atomic Data
    let mut builder = HttpResponse::Ok();
    let path_result = context.store.get_path(&path, &context.mapping)?;
    match content_type {
        ContentType::JSON => {
            builder.set(http::header::ContentType::json());
            //   let body = context.store.resource_to_json(&subject, 1)?;
            Ok(builder.body("Not implemented"))
        }
        ContentType::HTML => {
            let mut propvals: Vec<PropVal> = Vec::new();
            match path_result {
                atomic_lib::store::PathReturn::Subject(subject) => {
                    let resource = context.store.get(&subject).ok_or("Resource not found")?;
                    for (property, value) in resource.iter() {
                        let fullprop = context.store.get_property(property)?;
                        let native_value = context.store.get_native_value(value, &fullprop.data_type)?;
                        let propval = PropVal {
                            property: fullprop,
                            value: crate::render_atom::value_to_html(native_value),
                        };
                        propvals.push(propval);
                    }
                }
                atomic_lib::store::PathReturn::Atom(atom) => {
                    propvals.push(
                        PropVal {
                            property: context.store.get_property(&atom.property.subject)?,
                            value: crate::render_atom::value_to_html(atom.native_value),
                        }
                    );
                }
            }
            builder.set(http::header::ContentType::html());
            let mut tera_context = TeraCtx::new();

            #[derive(Serialize)]
            struct PropVal {
                property: Property,
                value: String,
            }

            tera_context.insert("propvals", &propvals);
            tera_context.insert("path", &path);
            let body = context.tera.render("path.html", &tera_context).unwrap();
            Ok(builder.body(body))
        }
        ContentType::AD3 => {
            builder.set(http::header::ContentType::html());
            //   let body = context.store.resource_to_ad3(&subject, Some(&context.config.domain))?;
            Ok(builder.body("Not implemented"))
        }
    }
}
