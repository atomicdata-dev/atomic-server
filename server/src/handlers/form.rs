//! `/form/:id` endpoints — Phase 3 of Atomic Forms
//! (`planning/atomic-forms.md`). Submissions are written by the store's own
//! default agent (there is no visitor identity); publish-state gating plus
//! the field validation in `crate::forms` replace a rights check.
//! Responses are plain JSON, not JSON-AD — this runtime never parses Atomic
//! Data, so it gets its own small error type instead of `AtomicServerError`.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use actix_web::{http::StatusCode, web, HttpRequest, HttpResponse, ResponseError};
use atomic_lib::{urls, AtomicError, Resource, Storelike, Value};
use serde::Deserialize;
use serde_json::json;

use crate::{
    appstate::AppState,
    forms,
    handlers::download::{download_file_handler_partial, DownloadParams},
    handlers::single_page_app::generate_nonce,
};

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
    FormApiError::new(
        StatusCode::GONE,
        "This form isn't accepting responses right now.",
    )
}

/// `?code=` on the viewer-facing routes (Phase 6 "Private links"): the invite
/// code a visitor presents for an invite-only form.
#[derive(Deserialize)]
pub struct AccessQuery {
    code: Option<String>,
}

/// Enforces a Form's `form-access` mode. Public forms always pass. For
/// invite-only forms the presented code must exist, belong to this form, and
/// be unused — checked *without* consuming, so a visitor can load the form
/// (definition) and still submit with the same code. Consumption happens
/// atomically in [submit_form].
async fn check_form_access(
    store: &atomic_lib::Db,
    form: &Resource,
    code: Option<&str>,
) -> Result<(), FormApiError> {
    if !forms::is_invite_only(form) {
        return Ok(());
    }

    let forbidden = |message: &str| FormApiError::new(StatusCode::FORBIDDEN, message);

    let Some(code) = code.filter(|c| !c.is_empty()) else {
        return Err(forbidden(
            "This form is invite-only. Ask the form owner for an invite link.",
        ));
    };

    match forms::check_invite_code(store, form, code).await {
        forms::InviteCodeCheck::Valid(_) => Ok(()),
        forms::InviteCodeCheck::Used => Err(forbidden(
            "This invite link has already been used. Ask the form owner for a new one.",
        )),
        forms::InviteCodeCheck::Invalid => Err(forbidden(
            "This invite link isn't valid. Ask the form owner for a new one.",
        )),
    }
}

/// Resolves `{id}` to a Form resource, confirming it really is a Form and is
/// currently published. Shared by both handlers.
async fn resolve_published_form(
    store: &atomic_lib::Db,
    id: &str,
) -> Result<Resource, FormApiError> {
    let form = forms::resolve_form(store, id)
        .await
        .map_err(|_| not_found())?;

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
pub async fn form_page(
    path: web::Path<String>,
    access: web::Query<AccessQuery>,
    appstate: web::Data<AppState>,
) -> HttpResponse {
    let store = &appstate.store;

    let mut form = match resolve_published_form(store, &path.into_inner()).await {
        Ok(form) => form,
        Err(err) => return not_available_page(err.status, &err.message),
    };

    // Invite-only gating happens here on the server (unlike `?embed=1`, which
    // stays client-side) — the definition is injected into the HTML below, so
    // serving the page without a valid code would leak the questions.
    if let Err(err) = check_form_access(store, &form, access.code.as_deref()).await {
        return not_available_page(err.status, &err.message);
    }

    let mut definition = match forms::build_form_definition(store, &form).await {
        Ok(d) => d,
        Err(e) => return not_available_page(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    definition.id = match forms::mint_publish_slug(store, &mut form).await {
        Ok(slug) => slug,
        Err(e) => return not_available_page(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    fill_image_url(&mut definition);
    definition.captcha = Some(appstate.captcha.client_config(&definition.id));

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
            // `worker-src blob:` — the ALTCHA widget's single-file bundle
            // spawns its proof-of-work Web Workers from blob: URLs.
            format!(
                "script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; worker-src 'self' blob:; frame-ancestors *"
            ),
        ))
        .body(body)
}

/// Minimal, dependency-free HTML page for unknown/unpublished/errored forms
/// — no JS bundle needed since there's nothing to render. Colors mirror
/// `@tomic/form-renderer`'s palette (`browser/form-renderer/src/style.css`)
/// so a visitor doesn't see a jarring generic error page after a form-styled
/// runtime would otherwise have loaded.
///
/// Shares `form_page`'s `frame-ancestors *` policy (Phase 6 "Embedding" —
/// forms are embeddable by any site once published, no auth boundary is
/// involved) so a stale/unpublished embed shows this friendly card instead
/// of a browser-blocked blank frame.
fn not_available_page(status: StatusCode, message: &str) -> HttpResponse {
    let escaped = message
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\
         <title>Form not available</title>\
         <style>\
         :root{{--bg:#ffffff;--text:#1a1a1a;--text-light:#6b7280;--border:#d9dce1;--radius:0.5rem}}\
         @media (prefers-color-scheme: dark){{:root{{--bg:#16181d;--text:#f2f2f2;--text-light:#a0a5ad;--border:#33363d}}}}\
         body{{margin:0;font-family:system-ui,-apple-system,sans-serif;display:flex;\
         min-height:100vh;align-items:center;justify-content:center;padding:1.5rem;\
         color:var(--text);background:var(--bg)}}\
         .card{{max-width:26rem;text-align:center;padding:2rem 1.75rem;\
         border:1px solid var(--border);border-radius:var(--radius)}}\
         h1{{font-size:1.1rem;margin:0 0 0.5rem}}\
         p{{margin:0;color:var(--text-light);line-height:1.5}}\
         </style>\
         </head><body><div class=\"card\"><h1>Form not available</h1><p>{escaped}</p></div></body></html>"
    );

    HttpResponse::build(status)
        .content_type("text/html")
        .insert_header((
            "Cache-Control",
            "no-store, no-cache, must-revalidate, private",
        ))
        .insert_header(("Content-Security-Policy", "frame-ancestors *"))
        .body(body)
}

/// `GET /form/{id}/definition` — denormalized JSON for a published form.
/// Mints and persists a publish slug on first successful fetch if the form
/// doesn't have one yet (see `crate::forms` module docs).
pub async fn get_definition(
    path: web::Path<String>,
    access: web::Query<AccessQuery>,
    appstate: web::Data<AppState>,
) -> Result<HttpResponse, FormApiError> {
    let store = &appstate.store;
    let mut form = resolve_published_form(store, &path.into_inner()).await?;
    check_form_access(store, &form, access.code.as_deref()).await?;

    let mut definition = forms::build_form_definition(store, &form)
        .await
        .map_err(internal_error)?;
    definition.id = forms::mint_publish_slug(store, &mut form)
        .await
        .map_err(internal_error)?;
    fill_image_url(&mut definition);
    definition.captcha = Some(appstate.captcha.client_config(&definition.id));

    Ok(HttpResponse::Ok().json(definition))
}

/// `GET /form/{id}/challenge` — a fresh proof-of-work challenge for the
/// published form's captcha widget. Stateless to issue (HMAC-signed), so no
/// bookkeeping happens here; one-time use is enforced at verification.
/// Deliberately not invite-code-gated: a challenge leaks nothing about the
/// form, and gating it would mean threading the code through the widget's
/// challenge URL for zero security gain.
pub async fn get_challenge(
    path: web::Path<String>,
    appstate: web::Data<AppState>,
) -> Result<HttpResponse, FormApiError> {
    resolve_published_form(&appstate.store, &path.into_inner()).await?;

    let challenge = appstate.captcha.issue().map_err(internal_error)?;
    Ok(HttpResponse::Ok()
        .insert_header((
            "Cache-Control",
            "no-store, no-cache, must-revalidate, private",
        ))
        .json(challenge))
}

/// Points the definition's styling at the publish-gated image route (see
/// [form_image]) — the visitor has no agent, so the File's own rights-checked
/// `/download` URL would be unreachable. Requires `definition.id` to be set.
fn fill_image_url(definition: &mut forms::FormDefinition) {
    if definition.styling.has_image {
        definition.styling.image_url = Some(format!("/form/{}/image", definition.id));
    }
}

/// `GET /form/{id}/image` — serves the published form's `cover-image` File.
/// Publish-gating replaces the rights check `/download` would do (decision #3
/// in `planning/atomic-forms.md`: publishing is a property, not a rights
/// change, so the File stays private). Delegates to the shared download
/// handler: stored mimetype (SVG renders in `<img>`; `Content-Disposition:
/// attachment` + `nosniff` keep it from ever executing as a document) and
/// `?w=&q=&f=` image processing come with it.
/// Deliberately not invite-code-gated: the cover image is branding, not
/// answers/questions, and gating it would break the browser cache header
/// below (per-code URLs) for zero meaningful confidentiality gain.
pub async fn form_image(
    path: web::Path<String>,
    params: web::Query<DownloadParams>,
    req: HttpRequest,
    appstate: web::Data<AppState>,
) -> Result<HttpResponse, FormApiError> {
    let store = &appstate.store;
    let form = resolve_published_form(store, &path.into_inner()).await?;

    let image_subject = form
        .get(urls::COVER_IMAGE)
        .map_err(|_| not_found())?
        .to_string();
    let file = store
        .get_resource(&image_subject.into())
        .await
        .map_err(|_| not_found())?;

    let mut response = download_file_handler_partial(&file, &req, &params, &appstate)
        .map_err(|e| internal_error(e.to_string()))?;
    // Same-URL responses are stable while published; let browsers cache them
    // for a bit instead of re-fetching per page view.
    response.headers_mut().insert(
        actix_web::http::header::CACHE_CONTROL,
        actix_web::http::header::HeaderValue::from_static("public, max-age=3600"),
    );
    Ok(response)
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

    // Invite-only pre-check (non-consuming): fail fast on a missing/invalid/
    // already-used code before the visitor's one-time captcha payload gets
    // burned by the verification below. The authoritative check-and-consume
    // runs again under the per-form lock right before the row is written.
    let invite_code = body
        .get(forms::INVITE_CODE_FIELD)
        .and_then(|v| v.as_str())
        .map(str::to_string);
    check_form_access(store, &form, invite_code.as_deref()).await?;

    // Proof-of-work captcha (Phase 6): the widget rides its solved payload
    // along in the body's top-level `altcha` field. Verified + consumed
    // (one-time use) before any validation work happens.
    appstate
        .captcha
        .verify(body.get("altcha").and_then(|v| v.as_str()))
        .await
        .map_err(|message| FormApiError::new(StatusCode::BAD_REQUEST, message))?;

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

    let table = store
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

    // Stamp the owning drive. Client-created resources get this at genesis
    // (and the commit handler's safety net covers rights-validated commits),
    // but this server-agent `save()` path skips both — and without a `drive`
    // the CommitMonitor's drive-scoped fan-out finds no owning drive, so
    // connected clients never receive the new row over WS and the results
    // table stays stale until a full reload. `set_unsafe` because `drive`
    // has no resolvable Property resource (same as the commit handler's
    // safety net).
    if let Some(drive) = table.get_drive().or_else(|| form.get_drive()) {
        row.set_unsafe(
            urls::DRIVE_PROP.into(),
            Value::AtomicUrl(drive.to_string().into()),
        )
        .map_err(internal_error)?;
    }

    for (property, value) in coerced {
        row.set(property, value, store)
            .await
            .map_err(internal_error)?;
    }

    // Genesis (`did:ad:`) rather than plain `save()`: `new_instance` mints an
    // `internal:/response/{id}` subject, which resolves to a different string
    // per transport (`http://…` over WS push, `internal:/…` via drive sync) —
    // the client then indexes the same row under two identities. Every other
    // table row is a DID resource with one canonical id; match that.
    if forms::is_invite_only(&form) {
        // Commits are not compare-and-swap, so check-and-consume is
        // serialized with an in-process per-form mutex (single server
        // process — same layer as the rate limiter above). Inside the lock,
        // `used-at` is written *before* the row: the reverse order would
        // allow a double submission when row creation races or fails.
        let lock = form_submit_lock(&form);
        let _guard = lock.lock().await;

        match forms::check_invite_code(store, &form, invite_code.as_deref().unwrap_or_default())
            .await
        {
            forms::InviteCodeCheck::Valid(mut code) => {
                forms::consume_invite_code(store, &mut code)
                    .await
                    .map_err(internal_error)?;
            }
            // The pre-check passed, so a concurrent submit consumed the code
            // in the meantime (or the owner revoked it mid-flight).
            _ => {
                return Err(FormApiError::new(
                    StatusCode::FORBIDDEN,
                    "This invite link has already been used. Ask the form owner for a new one.",
                ));
            }
        }

        row.save_as_genesis(store).await.map_err(internal_error)?;
    } else {
        row.save_as_genesis(store).await.map_err(internal_error)?;
    }

    Ok(HttpResponse::Created().json(json!({ "ok": true })))
}

/// Per-form lock serializing invite-code check-and-consume in [submit_form].
/// Entries are never pruned — one `Arc<Mutex>` per invite-only form ever
/// submitted to since the last restart is negligible.
fn form_submit_lock(form: &Resource) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));

    locks
        .lock()
        .unwrap()
        .entry(form.get_subject().pure_id())
        .or_default()
        .clone()
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
