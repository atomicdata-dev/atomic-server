use crate::{appstate::AppState, content_types::ContentType, content_types::get_accept, errors::{AppError, BetterResult}};
use actix_web::{web, HttpResponse};
use atomic_lib::{Storelike};
use std::{
    sync::{Mutex},
};

/// Respond to a single resource.
/// The URL should match the Subject of the resource.
pub async fn get_resource(
    subject_end: Option<web::Path<String>>,
    data: web::Data<Mutex<AppState>>,
    req: actix_web::HttpRequest,
) -> BetterResult<HttpResponse> {
    let context = data.lock().unwrap();

    let mut content_type = get_accept(req.headers());
    let base_url = &context.config.local_base_url;
    // Get the subject from the path, or return the home URL
    let subject = if let Some(subj_end) = subject_end {
        let mut subj_end_string = subj_end.as_str();
        if content_type == ContentType::HTML {
            if let Some((ext, path)) = try_extension(subj_end_string) {
                content_type = ext;
                subj_end_string = path;
            }
        }
        // Check extensions and set datatype. Harder than it looks to get right...
        // This might not be the best way of creating the subject. But I can't access the full URL from any actix stuff!
        let querystring = if req.query_string().is_empty() {
            "".to_string()
        } else {
            format!("?{}", req.query_string())
        };
        let subject = format!(
            "{}/{}{}",
            base_url, subj_end_string, querystring
        );
        subject
    } else {
        String::from(base_url)
    };
    let store = &context.store;
    let mut builder = HttpResponse::Ok();
    log::info!("get_resource: {} as {}", subject, content_type.to_mime());
    builder.header("Content-Type", content_type.to_mime());
    let resource = store
        .get_resource_extended(&subject)
        // TODO: Don't always return 404 - only when it's actually not found!
        .map_err(|e| AppError::not_found(e.to_string()))?;
    match content_type {
        ContentType::JSON => {
            let body = resource.to_json(store)?;
            Ok(builder.body(body))
        }
        ContentType::JSONLD => {
            let body = resource.to_json_ld(store)?;
            Ok(builder.body(body))
        }
        ContentType::JSONAD => {
            let body = resource.to_json_ad()?;
            Ok(builder.body(body))
        }
        ContentType::HTML => {
            let body = resource.to_json_ad()?;
            Ok(builder.body(body))
        }
        ContentType::AD3 => {
            let body = resource.to_ad3()?;
            Ok(builder.body(body))
        }
        ContentType::TURTLE | ContentType::NT => {
            let atoms = store.get_resource(&subject)?.to_atoms()?;
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
            "jsonad" => ContentType::JSONAD,
            "html" => ContentType::HTML,
            "ttl" => ContentType::TURTLE,
            _ => return None,
        };
        return Some((content_type, path));
    }
    None
}
