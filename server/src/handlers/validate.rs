use crate::appstate::AppState;
use crate::errors::BetterResult;
use actix_web::{http, web, HttpResponse};
use atomic_lib::Storelike;
use serde::Deserialize;
use std::sync::Mutex;
use tera::Context as TeraCtx;

#[derive(Deserialize, Debug)]
pub struct ValidationQuery {
    pub ad3: Option<String>,
    pub url: Option<String>,
}

/// Validation handler.
/// Accepts an AD3 string and validates it!
pub async fn validate(
    data: web::Data<Mutex<AppState>>,
    // req: actix_web::HttpRequest,
    query: web::Query<ValidationQuery>,
) -> BetterResult<HttpResponse> {
    let context = data.lock().unwrap();
    // let store = &mut context.store;
    let mut builder = HttpResponse::Ok();
    let tempstore = atomic_lib::Store::init();
    log::info!("validate {:?}", query.ad3);
    let report: String = match query.ad3.as_ref() {
        Some(ad3) => {
            match atomic_lib::parse::parse_ad3(ad3) {
                Ok(atoms) => {
                  tempstore.add_atoms(atoms)?;
                  tempstore.validate().to_string()
                },
                Err(e) => e.to_string(),
            }
        }
        None => "insert an ad3 string".into(),
    };
    builder.set(http::header::ContentType::html());
    let mut tera_context = TeraCtx::new();
    tera_context.insert("ad3", &query.ad3);
    tera_context.insert("report", &report);
    let body = context.tera.render("validate.html", &tera_context)?;
    Ok(builder.body(body))
}
