use actix_web::{web, HttpResponse};
use std::sync::Mutex;
use crate::errors::BetterResult;
use crate::appstate::AppState;
use tera::{Context as TeraCtx};

pub async fn home(
  data: web::Data<Mutex<AppState>>,
) -> BetterResult<HttpResponse> {
  let tera_context = TeraCtx::new();
  let context = data.lock().unwrap();
  let body = context
              .tera
              .render("home.html", &tera_context)
              .unwrap();
  let mut builder = HttpResponse::Ok();
  Ok(builder.body(body))
}
