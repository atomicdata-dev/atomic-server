use crate::{
    appstate::AppState, content_types::get_accept, content_types::ContentType,
    errors::BetterResult, render::propvals::from_hashmap_resource,
};
use actix_web::{web, HttpResponse};
use atomic_lib::Storelike;
use std::sync::Mutex;
use tera::Context as TeraCtx;

/// Respond to a single resource.
/// The URL should match the Subject of the resource.
pub async fn get_resource(
    subject_end: web::Path<String>,
    data: web::Data<Mutex<AppState>>,
    req: actix_web::HttpRequest,
) -> BetterResult<HttpResponse> {
    let context = data.lock().unwrap();
    log::info!("subject_end: {}", subject_end);
    let mut subj_end_string = subject_end.as_str();
    let mut content_type = get_accept(req);
    // Check extensions and set datatype. Harder than it looks to get right...
    if content_type == ContentType::HTML {
        if let Some((ext, path)) = try_extension(subj_end_string) {
            content_type = ext;
            subj_end_string = path;
        }
    }
    let subject = format!("{}{}", &context.config.local_base_url, subj_end_string);
    let store = &context.store;
    let mut builder = HttpResponse::Ok();
    log::info!("get_resource: {} - {}", subject, content_type.to_mime());
    builder.header("Content-Type", content_type.to_mime());
    let resource = store.get_resource_extended(&subject)?;
    match content_type {
        ContentType::JSON => {
            let body = resource.to_json(store, 1, false)?;
            Ok(builder.body(body))
        }
        ContentType::JSONLD => {
            let body = resource.to_json(store, 1, true)?;
            Ok(builder.body(body))
        }
        ContentType::HTML => {
            let mut tera_context = TeraCtx::new();
            // Check if there is a registered view for this class
            let mut body: String = format!("Custom view for {} not correctly implemented. The function should overwrite this string.", subject);

            if let Ok(classes_val) = resource.get_shortname("is-a") {
                if let Ok(classes_vec) = classes_val.to_vec() {
                    for class in classes_vec {
                        match class.as_ref() {
                            atomic_lib::urls::COLLECTION => {
                                body = crate::views::collection::render_collection(&resource, &context);
                            },
                            _ => {},
                        }
                    }
                }
            } else {
                // If not, fall back to the default renderer
                let resource = resource.to_plain();
                let propvals = from_hashmap_resource(&resource, store, subject)?;
                tera_context.insert("resource", &propvals);
                body = context.tera.render("resource.html", &tera_context)?;
            }
            Ok(builder.body(body))
        }
        ContentType::AD3 => {
            let body = resource.to_ad3()?;
            Ok(builder.body(body))
        }
        ContentType::TURTLE | ContentType::NT => {
            let atoms = atomic_lib::resources::resourcestring_to_atoms(
                &subject,
                store.get_resource_string(&subject)?,
            );
            let body = atomic_lib::serialize::atoms_to_ntriples(atoms, store)?;
            Ok(builder.body(body))
        }
    }
}

/// Finds the extension
fn try_extension(path: &str) -> Option<(ContentType, &str)> {
    let items: Vec<&str> = path.split('.').collect();
    if items.len() == 2 {
        let path = items[0];
        let content_type = match items[1] {
            "ad3" => ContentType::AD3,
            "json" => ContentType::JSON,
            "jsonld" => ContentType::JSONLD,
            "html" => ContentType::HTML,
            "ttl" => ContentType::TURTLE,
            _ => return None,
        };
        return Some((content_type, path));
    }
    None
}
