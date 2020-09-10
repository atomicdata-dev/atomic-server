use crate::{
    appstate::AppState, content_types::get_accept, content_types::ContentType,
    errors::BetterResult, render::propvals::from_hashmap_resource,
};
use actix_web::{http, web, HttpResponse};
use atomic_lib::Storelike;
use std::path::Path;
use std::sync::Mutex;
use tera::Context as TeraCtx;

pub async fn get_resource(
    _id: web::Path<String>,
    data: web::Data<Mutex<AppState>>,
    req: actix_web::HttpRequest,
) -> BetterResult<HttpResponse> {
    let path = Path::new(_id.as_str());
    let id: &str = path.file_stem().unwrap().to_str().ok_or("Issue with URL")?;

    let content_type = get_accept(req);
    if content_type == ContentType::HTML {
        let _content_type: ContentType = match path.extension() {
            Some(extension) => match extension
                .to_str()
                .ok_or("Extension cannot be parsed. Try a different URL.")?
            {
                "ad3" => ContentType::AD3,
                "json" => ContentType::JSON,
                "jsonld" => ContentType::JSONLD,
                "html" => ContentType::HTML,
                _ => ContentType::HTML,
            },
            None => ContentType::HTML,
        };
    }

    log::info!("id: {:?}", id);
    let context = data.lock().unwrap();
    // This is how locally items are stored (which don't know their full subject URL) in Atomic Data
    let subject = format!("_:{}", id);
    let mut builder = HttpResponse::Ok();
    match content_type {
        ContentType::JSON => {
            builder.set(http::header::ContentType::json());
            let body = context.store.resource_to_json(&subject, 1, false)?;
            Ok(builder.body(body))
        }
        ContentType::JSONLD => {
            builder.set(http::header::ContentType::json());
            let body = context.store.resource_to_json(&subject, 1, true)?;
            Ok(builder.body(body))
        }
        ContentType::HTML => {
            builder.set(http::header::ContentType::html());
            let mut tera_context = TeraCtx::new();
            let resource = context.store.get_resource_string(&subject)?;

            let propvals = from_hashmap_resource(&resource, &context.store, subject)?;

            tera_context.insert("resource", &propvals);
            let body = context.tera.render("resource.html", &tera_context).unwrap();
            Ok(builder.body(body))
        }
        ContentType::AD3 => {
            builder.set(http::header::ContentType::html());
            let body = context
                .store
                .resource_to_ad3(subject, Some(&context.config.local_base_url))?;
            Ok(builder.body(body))
        }
    }
}
