//! `/form/:id` endpoints — Phase 3 of Atomic Forms
//! (`planning/atomic-forms.md`). Submissions are written by the store's own
//! default agent (there is no visitor identity); publish-state gating plus
//! the field validation in `atomic_lib::forms` replace a rights check.
//! Responses are plain JSON, not JSON-AD — this runtime never parses Atomic
//! Data, so it gets its own small error type instead of `AtomicServerError`.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use actix_web::{http::StatusCode, web, HttpRequest, HttpResponse, ResponseError};
use atomic_lib::{forms, urls, AtomicError, Resource, Storelike, Value};
use serde_json::json;

use crate::{appstate::AppState, handlers::single_page_app::generate_nonce};

pub struct FormApiError {
    status: StatusCode,
    message: String,
}

impl FormApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl std::fmt::Debug for FormApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::fmt::Display for FormApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for FormApiError {}

impl ResponseError for FormApiError {
    fn status_code(&self) -> StatusCode {
        self.status
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status).json(json!({ "error": self.message }))
    }
}

impl From<AtomicError> for FormApiError {
    fn from(error: AtomicError) -> Self {
        let status = match error.error_type {
            atomic_lib::AtomicErrorType::NotFoundError => StatusCode::NOT_FOUND,
            atomic_lib::AtomicErrorType::UnauthorizedError => StatusCode::UNAUTHORIZED,
            atomic_lib::AtomicErrorType::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            _ => StatusCode::BAD_REQUEST,
        };
        FormApiError::new(status, error.to_string())
    }
}

fn internal_error(e: impl std::fmt::Display) -> FormApiError {
    FormApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn not_found() -> FormApiError {
    FormApiError::new(StatusCode::NOT_FOUND, "Form not found")
}

fn unpublished() -> FormApiError {
    FormApiError::new(StatusCode::GONE, "This form is not published")
}

/// Resolves `{id}` to a Form resource, confirming it really is a Form and is
/// currently published. Shared by both handlers.
async fn resolve_published_form(store: &atomic_lib::Db, id: &str) -> Result<Resource, FormApiError> {
    let form = forms::resolve_form(store, id).await.map_err(|_| not_found())?;

    let classes = form
        .get(urls::IS_A)
        .and_then(|v| v.to_subjects(None))
        .unwrap_or_default();
    if !classes.iter().any(|c| c == urls::FORM) {
        return Err(not_found());
    }

    if form.get(urls::FORM_PUBLISHED_AT).is_err() {
        return Err(unpublished());
    }

    Ok(form)
}

/// `GET /form/{id}` — the published-form HTML runtime (Phase 4). Serves
/// `form-app`'s built `index.html` (embedded via `build.rs::copy_form_assets`
/// into `assets_tmp/form-assets/`) with the definition JSON injected inline
/// as `window.__FORM_DEFINITION__`, killing the fetch waterfall — mirrors
/// `single_page_app.rs`'s meta-tag injection for the same reason. Falls back
/// to a minimal standalone page (no JS bundle needed) when the form is
/// unknown or unpublished.
pub async fn form_page(path: web::Path<String>, appstate: web::Data<AppState>) -> HttpResponse {
    let store = &appstate.store;

    let mut form = match resolve_published_form(store, &path.into_inner()).await {
        Ok(form) => form,
        Err(err) => return not_available_page(err.status, &err.message),
    };

    let mut definition = match forms::build_form_definition(store, &form).await {
        Ok(d) => d,
        Err(e) => return not_available_page(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    definition.id = match forms::mint_publish_slug(store, &mut form).await {
        Ok(slug) => slug,
        Err(e) => return not_available_page(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let nonce = match generate_nonce() {
        Ok(n) => n,
        Err(_) => return not_available_page(StatusCode::INTERNAL_SERVER_ERROR, "Server error"),
    };
    let definition_json = serde_json::to_string(&definition).unwrap_or_default();
    let template = include_str!("../../assets_tmp/form-assets/index.html");

    let inject = format!(
        "<script nonce=\"{nonce}\">window.__FORM_DEFINITION__ = {definition_json};</script>"
    );
    let body = template
        .replace("<!-- { inject_definition } -->", &inject)
        .replace("ATOMICSERVER_NONCE", &nonce);

    HttpResponse::Ok()
        .content_type("text/html")
        .insert_header((
            "Cache-Control",
            "no-store, no-cache, must-revalidate, private",
        ))
        .insert_header((
            "Content-Security-Policy",
            format!(
                "script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
            ),
        ))
        .body(body)
}

/// Minimal, dependency-free HTML page for unknown/unpublished/errored forms
/// — no JS bundle needed since there's nothing to render.
fn not_available_page(status: StatusCode, message: &str) -> HttpResponse {
    let escaped = message
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\
         <title>Form not available</title>\
         <style>body{{font-family:system-ui,sans-serif;display:flex;justify-content:center;\
         padding:4rem 1rem;color:#1a1a1a;background:#fff}}\
         p{{max-width:28rem;text-align:center}}\
         @media (prefers-color-scheme: dark){{body{{color:#f2f2f2;background:#16181d}}}}</style>\
         </head><body><p>{escaped}</p></body></html>"
    );

    HttpResponse::build(status)
        .content_type("text/html")
        .insert_header((
            "Cache-Control",
            "no-store, no-cache, must-revalidate, private",
        ))
        .body(body)
}

/// `GET /form/{id}/definition` — denormalized JSON for a published form.
/// Mints and persists a publish slug on first successful fetch if the form
/// doesn't have one yet (see `atomic_lib::forms` module docs).
pub async fn get_definition(
    path: web::Path<String>,
    appstate: web::Data<AppState>,
) -> Result<HttpResponse, FormApiError> {
    let store = &appstate.store;
    let mut form = resolve_published_form(store, &path.into_inner()).await?;

    let mut definition = forms::build_form_definition(store, &form)
        .await
        .map_err(internal_error)?;
    definition.id = forms::mint_publish_slug(store, &mut form)
        .await
        .map_err(internal_error)?;

    Ok(HttpResponse::Ok().json(definition))
}

/// `POST /form/{id}/submit` — body `{ "values": { "<propertySubject>": <json>, ... } }`.
/// Validates against the form definition and writes a submission row as a
/// child of the target table, signed by the store's default agent.
pub async fn submit_form(
    path: web::Path<String>,
    body: web::Json<serde_json::Value>,
    req: HttpRequest,
    appstate: web::Data<AppState>,
) -> Result<HttpResponse, FormApiError> {
    check_rate_limit(&req)?;

    let store = &appstate.store;
    let form = resolve_published_form(store, &path.into_inner()).await?;

    let honeypot_filled = body
        .get(forms::HONEYPOT_FIELD)
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty());
    if honeypot_filled {
        return Err(FormApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid submission",
        ));
    }

    let definition = forms::build_form_definition(store, &form)
        .await
        .map_err(internal_error)?;

    let values = body
        .get("values")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    let coerced = match forms::validate_submission(&definition, &values) {
        Ok(coerced) => coerced,
        Err(errors) => {
            return Ok(HttpResponse::BadRequest().json(json!({ "errors": errors })));
        }
    };

    let table_subject = form
        .get(urls::FORM_TARGET_TABLE)
        .map_err(|_| internal_error("Form is missing its target table"))?
        .to_string();
    let data_class_subject = form
        .get(urls::FORM_DATA_CLASS)
        .map_err(|_| internal_error("Form is missing its data class"))?
        .to_string();

    store
        .get_resource(&table_subject.clone().into())
        .await
        .map_err(|_| internal_error("Form's target table no longer exists"))?;

    let mut row = Resource::new_instance(&data_class_subject, store)
        .await
        .map_err(|_| internal_error("Form's data class no longer exists"))?;
    row.set(
        urls::PARENT.into(),
        Value::AtomicUrl(table_subject.into()),
        store,
    )
    .await
    .map_err(internal_error)?;

    for (property, value) in coerced {
        row.set(property, value, store).await.map_err(internal_error)?;
    }

    row.save(store).await.map_err(internal_error)?;

    Ok(HttpResponse::Created().json(json!({ "ok": true })))
}

// ── Per-IP rate limiting (fixed window, in-process) ──────────────────────

const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const RATE_LIMIT_MAX: usize = 10;

fn rate_limiter() -> &'static Mutex<HashMap<String, VecDeque<Instant>>> {
    static LIMITER: OnceLock<Mutex<HashMap<String, VecDeque<Instant>>>> = OnceLock::new();
    LIMITER.get_or_init(|| Mutex::new(HashMap::new()))
}

fn check_rate_limit(req: &HttpRequest) -> Result<(), FormApiError> {
    let ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    let mut guard = rate_limiter().lock().unwrap();
    let now = Instant::now();
    let entry = guard.entry(ip).or_default();
    while let Some(front) = entry.front() {
        if now.duration_since(*front) > RATE_LIMIT_WINDOW {
            entry.pop_front();
        } else {
            break;
        }
    }
    if entry.len() >= RATE_LIMIT_MAX {
        return Err(FormApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many submissions, please try again later",
        ));
    }
    entry.push_back(now);
    Ok(())
}
