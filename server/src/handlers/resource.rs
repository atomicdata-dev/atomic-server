use crate::{
    appstate::AppState, content_types::get_accept, content_types::ContentType,
    errors::BetterResult, render::propvals::from_hashmap_resource,
};
use actix_web::{web, HttpResponse};
use atomic_lib::Storelike;
use std::path::Path;
use std::sync::Mutex;
use tera::Context as TeraCtx;

/// Respond to a single resource.
/// The URL should match the Subject of the resource.
pub async fn get_resource(
    subject_end: web::Path<String>,
    data: web::Data<Mutex<AppState>>,
    req: actix_web::HttpRequest,
) -> BetterResult<HttpResponse> {
    let mut context = data.lock()?;
    log::info!("subject_end: {}", subject_end);
    let subj_end_string = subject_end.to_string();
    let content_type = get_accept(req);
    // Check extensions and set datatype. Harder than it looks to get right...
    // let path = Path::new(&subj_end_string);
    // log::info!("path: {:?}", path);
    // if content_type == ContentType::HTML {
    //     content_type = match path.extension() {
    //         Some(extension) => match extension
    //             .to_str()
    //             .ok_or("Extension cannot be parsed. Try a different URL.")?
    //         {
    //             "ad3" => ContentType::AD3,
    //             "json" => ContentType::JSON,
    //             "jsonld" => ContentType::JSONLD,
    //             "html" => ContentType::HTML,
    //             "ttl" => ContentType::TURTLE,
    //             _ => ContentType::HTML,
    //         },
    //         None => ContentType::HTML,
    //     };
    // }
    let subject = format!("{}{}", &context.config.local_base_url, subj_end_string);
    let store = &mut context.store;
    let mut builder = HttpResponse::Ok();
    log::info!("get_resource: {} - {}", subject, content_type.to_mime());
    match content_type {
        ContentType::JSON => {
            builder.header("Content-Type", content_type.to_mime());
            let body = store.resource_to_json(&subject, 1, false)?;
            Ok(builder.body(body))
        }
        ContentType::JSONLD => {
            builder.header("Content-Type", content_type.to_mime());
            let body = store.resource_to_json(&subject, 1, true)?;
            Ok(builder.body(body))
        }
        ContentType::HTML => {
            builder.header("Content-Type", content_type.to_mime());
            let mut tera_context = TeraCtx::new();
            let resource = store.get_resource_string(&subject)?;
            let propvals = from_hashmap_resource(&resource, store, subject)?;
            tera_context.insert("resource", &propvals);
            let body = context.tera.render("resource.html", &tera_context)?;
            Ok(builder.body(body))
        }
        ContentType::AD3 => {
            builder.header("Content-Type", content_type.to_mime());
            let body = store
                .resource_to_ad3(&subject)?;
            Ok(builder.body(body))
        }
        ContentType::TURTLE | ContentType::NT => {
            builder.header("Content-Type", content_type.to_mime());
            let atoms = atomic_lib::resources::resourcestring_to_atoms(&subject,store.get_resource_string(&subject)?);
            let body = atomic_lib::serialize::atoms_to_ntriples(atoms, store)?;
            Ok(builder.body(body))
        }
    }
}
