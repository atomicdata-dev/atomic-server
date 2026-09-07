//! Browser-hosted OAuth and live-store imports. Provider details live in overlays.
mod catalog;
mod oauth;
mod storage;

use crate::{appstate::AppState, helpers::get_client_agent};
use actix_web::{
    cookie::{Cookie, SameSite},
    web, HttpRequest, HttpResponse,
};
use atomic_lib::agents::ForAgent;
use catalog::Integration;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Default)]
pub struct State {
    pending: Mutex<HashMap<String, Pending>>,
    jobs: Mutex<HashMap<String, Job>>,
}
struct Pending {
    agent: String,
    integration: Integration,
    verifier: String,
    client_id: String,
    client_secret: String,
    created: Instant,
}
#[derive(Clone, Serialize)]
struct Job {
    #[serde(skip)]
    updated: Option<Instant>,
    integration: String,
    status: String,
    message: String,
    drive: Option<String>,
}
const COOKIE: &str = "atomic-integration-state";
const CALLBACK: &str = "/integrations/callback";
const MAX_PENDING: usize = 128;
fn failure(status: actix_web::http::StatusCode, message: &str) -> HttpResponse {
    HttpResponse::build(status)
        .insert_header(("Cache-Control", "no-store"))
        .json(serde_json::json!({"error":message}))
}
async fn agent(req: &HttpRequest, app: &AppState) -> Result<String, HttpResponse> {
    let url = format!("{}{}", app.config.get_origin(), req.uri());
    match get_client_agent(req.headers(), app, &url).await {
        Ok(ForAgent::AgentSubject(agent)) => Ok(agent.to_string()),
        _ => Err(failure(
            actix_web::http::StatusCode::UNAUTHORIZED,
            "Sign in to connect an integration.",
        )),
    }
}
fn key(agent: &str, integration: &str) -> String {
    format!("{agent}|{integration}")
}

pub async fn list(app: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let agent = match agent(&req, &app).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    let integrations = match catalog::discover(&catalog::root()) {
        Ok(i) => i,
        Err(e) => return failure(actix_web::http::StatusCode::BAD_REQUEST, &e.to_string()),
    };
    let mut jobs = app.integrations.jobs.lock().unwrap();
    for job in jobs.values_mut() {
        if job.status == "authorizing"
            && job
                .updated
                .is_some_and(|t| t.elapsed() >= Duration::from_secs(600))
        {
            job.status = "failed".into();
            job.message = "Authorization expired. Connect again.".into();
        }
    }
    let list: Vec<_> = integrations.iter().map(|i| serde_json::json!({
        "id": i.id, "label": i.profile.label,
        "configured": std::env::var(&i.profile.client_id_env).is_ok_and(|s|!s.is_empty()) && std::env::var(&i.profile.client_secret_env).is_ok_and(|s|!s.is_empty()),
        "job": jobs.get(&key(&agent,&i.id))
    })).collect();
    HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-store"))
        .json(list)
}

#[derive(Deserialize)]
pub struct Start {
    integration: String,
}
pub async fn start(
    app: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<Start>,
) -> HttpResponse {
    let agent = match agent(&req, &app).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    let integration = match catalog::discover(&catalog::root()).and_then(|items| {
        items
            .into_iter()
            .find(|i| i.id == query.integration)
            .ok_or_else(|| anyhow::anyhow!("Unknown integration"))
    }) {
        Ok(i) => i,
        Err(e) => return failure(actix_web::http::StatusCode::BAD_REQUEST, &e.to_string()),
    };
    let (Ok(client_id), Ok(client_secret)) = (
        std::env::var(&integration.profile.client_id_env),
        std::env::var(&integration.profile.client_secret_env),
    ) else {
        return failure(actix_web::http::StatusCode::BAD_REQUEST,"The server administrator must configure this integration's OAuth client ID and secret.");
    };
    if client_id.is_empty() || client_secret.is_empty() {
        return failure(
            actix_web::http::StatusCode::BAD_REQUEST,
            "OAuth client credentials are empty.",
        );
    }
    let job_key = key(&agent, &integration.id);
    let state = oauth::nonce();
    let verifier = oauth::nonce();
    let origin = app.config.get_origin();
    let redirect = format!("{origin}{CALLBACK}");
    let url = match oauth::authorization_url(
        &integration.oauth,
        &client_id,
        &redirect,
        &state,
        &verifier,
    ) {
        Ok(url) => url,
        Err(_) => {
            return failure(
                actix_web::http::StatusCode::BAD_REQUEST,
                "Invalid OAuth authorization configuration",
            )
        }
    };
    {
        let mut pending = app.integrations.pending.lock().unwrap();
        pending.retain(|_, p| p.created.elapsed() < Duration::from_secs(600));
        if pending.len() >= MAX_PENDING {
            return failure(
                actix_web::http::StatusCode::TOO_MANY_REQUESTS,
                "Too many pending authorizations. Try again later.",
            );
        }
        let mut jobs = app.integrations.jobs.lock().unwrap();
        jobs.retain(|_, job| {
            job.updated
                .is_none_or(|t| t.elapsed() < Duration::from_secs(3600))
        });
        if jobs.get(&job_key).is_some_and(|j| j.status == "importing") {
            return failure(
                actix_web::http::StatusCode::CONFLICT,
                "This integration is already importing.",
            );
        }
        // Only the latest authorization for this user/integration can be completed.
        pending.retain(|_, p| key(&p.agent, &p.integration.id) != job_key);
        jobs.insert(
            job_key,
            Job {
                updated: Some(Instant::now()),
                integration: integration.id.clone(),
                status: "authorizing".into(),
                message: "Waiting for authorization".into(),
                drive: None,
            },
        );
        pending.insert(
            state.clone(),
            Pending {
                agent,
                integration,
                verifier,
                client_id,
                client_secret,
                created: Instant::now(),
            },
        );
    }
    let cookie = Cookie::build(COOKIE, state)
        .path(CALLBACK)
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(origin.starts_with("https:"))
        .max_age(actix_web::cookie::time::Duration::minutes(10))
        .finish();
    HttpResponse::Ok()
        .cookie(cookie)
        .insert_header(("Cache-Control", "no-store"))
        .json(serde_json::json!({"url":url}))
}

#[derive(Deserialize)]
pub struct Callback {
    state: String,
    code: Option<String>,
    error: Option<String>,
}
pub async fn callback(
    app: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<Callback>,
) -> HttpResponse {
    if req.cookie(COOKIE).is_none_or(|c| c.value() != query.state) {
        return failure(
            actix_web::http::StatusCode::BAD_REQUEST,
            "Authorization does not match this browser. Connect again from Sync.",
        );
    }
    let pending = app
        .integrations
        .pending
        .lock()
        .unwrap()
        .remove(&query.state);
    let Some(pending) = pending.filter(|p| p.created.elapsed() < Duration::from_secs(600)) else {
        return failure(
            actix_web::http::StatusCode::BAD_REQUEST,
            "Authorization expired or was already used. Connect again from Sync.",
        );
    };
    let job_key = key(&pending.agent, &pending.integration.id);
    if query.error.is_some() || query.code.as_deref().is_none_or(str::is_empty) {
        finish(
            &app,
            &job_key,
            Err(anyhow::anyhow!("Authorization was cancelled or denied.")),
        );
    } else {
        if let Some(job) = app.integrations.jobs.lock().unwrap().get_mut(&job_key) {
            job.status = "importing".into();
            job.message = "Importing data".into();
            job.updated = None;
        }
        let code = query.code.clone().unwrap();
        let app = app.clone();
        actix_web::rt::spawn(async move {
            let result =
                tokio::time::timeout(Duration::from_secs(1800), import(&app, pending, &code))
                    .await
                    .unwrap_or_else(|_| {
                        Err(anyhow::anyhow!(
                            "Import timed out; partial data was retained."
                        ))
                    });
            finish(&app, &job_key, result);
        });
    }
    let cookie = Cookie::build(COOKIE, "")
        .path(CALLBACK)
        .http_only(true)
        .max_age(actix_web::cookie::time::Duration::ZERO)
        .finish();
    HttpResponse::SeeOther()
        .cookie(cookie)
        .insert_header(("Location", "/app/sync"))
        .insert_header(("Cache-Control", "no-store"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .finish()
}
fn finish(app: &AppState, key: &str, result: anyhow::Result<String>) {
    if let Some(job) = app.integrations.jobs.lock().unwrap().get_mut(key) {
        job.updated = Some(Instant::now());
        match result {
            Ok(drive) => {
                job.status = "complete".into();
                job.message = "Import complete".into();
                job.drive = Some(drive);
            }
            Err(error) => {
                job.status = "failed".into();
                job.message = error.to_string();
            }
        }
    }
}
async fn import(app: &AppState, pending: Pending, code: &str) -> anyhow::Result<String> {
    let origin = app.config.get_origin();
    let integration = pending.integration;
    let fetch = oauth::OAuthFetch::exchange(
        integration.oauth,
        pending.client_id,
        pending.client_secret,
        &format!("{origin}{CALLBACK}"),
        code,
        &pending.verifier,
    )
    .await?;
    let prefix = format!(
        "{}-{}",
        integration.id,
        blake3::hash(pending.agent.as_bytes()).to_hex()
    );
    let namespace = integration
        .profile
        .constants
        .values()
        .cloned()
        .collect::<Vec<_>>()
        .join("/");
    let dataset = format!("{prefix}/{namespace}");
    let storage = storage::AgentStorage {
        inner: reflector_rs::AtomicStorage::new(
            Arc::new(app.store.clone()),
            reflector_rs::SubjectMapper::new(origin.clone()),
        )
        .with_drive_owner(Some(pending.agent))
        .with_dataset(dataset),
        prefix,
    };
    let drive = storage.inner.drive_subject();
    let client = syncables::SyncClient::new(
        syncables::ClientConfig {
            document: integration.document,
            overlays: integration.overlays,
            credentials: syncables::Credentials::Anonymous,
            constants: integration.profile.constants,
            ontology_base_url: origin.clone(),
        },
        fetch,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let result = client.sync(&storage).await;
    atomic_lib::search::build_search_index(&app.store)?;
    let report = result.map_err(|e| anyhow::anyhow!("{e}"))?;
    anyhow::ensure!(
        report.errors.is_empty(),
        "Import incomplete: {}",
        report.errors.join("; ")
    );
    Ok(drive.replacen("internal:", &origin, 1))
}
