//! Authenticated publication control; customer content is never served on the API origin.
use crate::{
    appstate::AppState,
    context::RequestContext,
    errors::{AtomicServerError, AtomicServerResult},
};
use actix_web::{
    guard,
    http::{header, Method},
    web, HttpRequest, HttpResponse,
};
use atomic_lib::{
    agents::ForAgent,
    hierarchy::check_write,
    website::{project_id, WebsitePackage, MAX_BYTES},
    Storelike,
};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectQuery {
    pub project: String,
    pub drive: String,
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Activate {
    pub expected_revision: u64,
    pub deployment: Option<String>,
}

fn base_origin(state: &AppState) -> AtomicServerResult<url::Url> {
    let raw = state.config.opts.website_origin.as_deref().ok_or_else(|| {
        AtomicServerError::bad_request(
            "Website hosting is disabled. Configure ATOMIC_WEBSITE_ORIGIN on your server.",
        )
    })?;
    let url = url::Url::parse(raw)
        .map_err(|_| AtomicServerError::bad_request("Invalid website origin"))?;
    let host = url.host_str().unwrap_or("");
    let api = url::Url::parse(&state.config.get_origin())
        .map_err(|e| AtomicServerError::bad_request(e.to_string()))?;
    let api_host = api.host_str().unwrap_or("");
    let overlaps = |other: &str| {
        host == other
            || host.ends_with(&format!(".{other}"))
            || other.ends_with(&format!(".{host}"))
    };
    let local = host.ends_with(".localhost") && matches!(api_host, "localhost" | "127.0.0.1");
    if host.is_empty()
        || !matches!(url.scheme(), "http" | "https")
        || (url.scheme() == "http" && !host.ends_with(".localhost"))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || (!local && overlaps(api_host))
        || state
            .config
            .opts
            .base_domain
            .as_deref()
            .is_some_and(overlaps)
    {
        return Err(AtomicServerError::bad_request("Use a separate HTTPS website domain (or http://sites.localhost:PORT for development), outside API/drive domains."));
    }
    Ok(url)
}
fn public_url(state: &AppState, project: &str) -> AtomicServerResult<String> {
    let mut url = base_origin(state)?;
    url.set_host(Some(&format!(
        "{}.{}",
        project_id(project),
        url.host_str().unwrap()
    )))
    .map_err(|e| AtomicServerError::bad_request(e.to_string()))?;
    Ok(url.to_string())
}
async fn authorize(
    state: &AppState,
    req: &HttpRequest,
    ctx: &RequestContext,
    body: &[u8],
    query: &ProjectQuery,
) -> AtomicServerResult<ForAgent> {
    base_origin(state)?;
    if query.project.is_empty()
        || query.drive.is_empty()
        || query.project.len() > 2048
        || query.drive.len() > 2048
    {
        return Err(AtomicServerError::bad_request(
            "Project and drive subjects are required",
        ));
    }
    let agent = crate::helpers::authenticate(req, state, ctx, body).await?;
    if matches!(agent, ForAgent::Public) {
        return Err(AtomicServerError::bad_request("Sign in to publish"));
    }
    let drive = state
        .store
        .get_resource(&query.drive.as_str().into())
        .await?;
    if !drive
        .get(atomic_lib::urls::IS_A)?
        .to_subjects(None)?
        .iter()
        .any(|s| s == atomic_lib::urls::DRIVE)
    {
        return Err(AtomicServerError::bad_request(
            "Publishing requires a drive root",
        ));
    }
    // Publishing is stronger than editing a page: it requires rights on the containing drive.
    check_write(&state.store, &drive, &agent).await?;
    let mut resource = state
        .store
        .get_resource(&query.project.as_str().into())
        .await?;
    check_write(&state.store, &resource, &agent).await?;
    if let Some(binding) = state.store.website_state(&project_id(&query.project))? {
        if binding.project != query.project || binding.drive != query.drive {
            return Err(AtomicServerError::bad_request("Website hosting belongs to a different drive. Transfer hosting explicitly before changing this binding."));
        }
    }
    let mut seen = std::collections::HashSet::new();
    for _ in 0..64 {
        if resource.get_subject() == drive.get_subject() {
            return Ok(agent);
        }
        if !seen.insert(resource.get_subject().to_string()) {
            break;
        }
        resource = resource.get_parent(&state.store).await?;
    }
    Err(AtomicServerError::bad_request(
        "Website is not in the selected drive",
    ))
}
fn response(
    state: &AppState,
    project: &str,
    value: Option<atomic_lib::db::website::WebsiteState>,
) -> AtomicServerResult<HttpResponse> {
    Ok(HttpResponse::Ok()
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .json(serde_json::json!({"url":public_url(state, project)?, "state":value})))
}
pub async fn status(
    state: web::Data<AppState>,
    req: HttpRequest,
    ctx: RequestContext,
    query: web::Query<ProjectQuery>,
) -> AtomicServerResult<HttpResponse> {
    authorize(&state, &req, &ctx, &[], &query).await?;
    response(
        &state,
        &query.project,
        state.store.website_state(&project_id(&query.project))?,
    )
}
pub async fn upload(
    state: web::Data<AppState>,
    req: HttpRequest,
    ctx: RequestContext,
    query: web::Query<ProjectQuery>,
    raw: web::Bytes,
) -> AtomicServerResult<HttpResponse> {
    let body: WebsitePackage = crate::helpers::parse_json(&raw)?;
    authorize(&state, &req, &ctx, &raw, &query).await?;
    body.validate()
        .map_err(|e| AtomicServerError::bad_request(e.to_string()))?;
    let value = state
        .store
        .website_upload(&query.project, &query.drive, &body)
        .await?;
    Ok(HttpResponse::Ok().insert_header((header::CACHE_CONTROL, "no-store")).json(serde_json::json!({"url":public_url(&state, &query.project)?, "state":value, "deployment":body.id()?})))
}
pub async fn asset_upload(
    state: web::Data<AppState>,
    req: HttpRequest,
    ctx: RequestContext,
    query: web::Query<ProjectQuery>,
    hash: web::Path<String>,
    body: web::Bytes,
) -> AtomicServerResult<HttpResponse> {
    authorize(&state, &req, &ctx, &body, &query).await?;
    state
        .store
        .website_put_asset(&query.project, &hash, &body)
        .await
        .map_err(|e| AtomicServerError::bad_request(e.to_string()))?;
    Ok(HttpResponse::NoContent().finish())
}
pub async fn asset_read(
    state: web::Data<AppState>,
    req: HttpRequest,
    ctx: RequestContext,
    query: web::Query<ProjectQuery>,
    hash: web::Path<String>,
) -> AtomicServerResult<HttpResponse> {
    authorize(&state, &req, &ctx, &[], &query).await?;
    let bytes = state
        .store
        .website_asset(&project_id(&query.project), &hash)
        .await?;
    Ok(match bytes {
        Some(bytes) => HttpResponse::Ok()
            .insert_header((header::CONTENT_TYPE, "application/octet-stream"))
            .insert_header((header::CACHE_CONTROL, "no-store"))
            .body(bytes),
        None => HttpResponse::NotFound().finish(),
    })
}
pub async fn activate(
    state: web::Data<AppState>,
    req: HttpRequest,
    ctx: RequestContext,
    query: web::Query<ProjectQuery>,
    raw: web::Bytes,
) -> AtomicServerResult<HttpResponse> {
    let body: Activate = crate::helpers::parse_json(&raw)?;
    let agent = authorize(&state, &req, &ctx, &raw, &query).await?;
    let value = state.store.website_activate(
        &project_id(&query.project),
        body.expected_revision,
        body.deployment.clone(),
        &agent.to_string(),
    )?;
    match value {
        Some(value) => response(&state, &query.project, Some(value)),
        None => Ok(HttpResponse::Conflict().insert_header((header::CACHE_CONTROL, "no-store")).json(serde_json::json!({"error":"Publication changed. Refresh hosting status and review before trying again."}))),
    }
}
/// Preview returns JSON only, authenticated for the entire package, not HTML on Atomic's origin.
pub async fn preview(
    state: web::Data<AppState>,
    req: HttpRequest,
    ctx: RequestContext,
    query: web::Query<ProjectQuery>,
    id: web::Path<String>,
) -> AtomicServerResult<HttpResponse> {
    authorize(&state, &req, &ctx, &[], &query).await?;
    let package = state
        .store
        .website_package(&project_id(&query.project), &id)
        .await?;
    Ok(HttpResponse::Ok()
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .json(package))
}

pub fn control_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/website-hosting")
            .app_data(web::PayloadConfig::new(2_000_000))
            .service(
                web::resource("/assets/{hash}")
                    .route(web::post().to(asset_upload))
                    .route(web::get().to(asset_read)),
            )
            .route("", web::get().to(status))
            // The package is read as `Bytes`, so its limit is a payload limit.
            .service(
                web::resource("/deployments")
                    .app_data(web::PayloadConfig::new(MAX_BYTES))
                    .route(web::post().to(upload)),
            )
            .service(
                web::resource("/activate")
                    .app_data(web::PayloadConfig::new(MAX_BYTES))
                    .route(web::post().to(activate)),
            )
            .route("/preview/{id}", web::get().to(preview)),
    );
}
fn website_host(host: &str, raw: &str) -> Option<String> {
    let base = url::Url::parse(raw).ok()?;
    let request = url::Url::parse(&format!("{}://{host}", base.scheme())).ok()?;
    let host = request.host_str()?;
    let domain = base.host_str()?;
    if host == domain {
        return Some(String::new());
    }
    host.strip_suffix(&format!(".{domain}")).map(str::to_owned)
}
/// Register before OAuth and API routes: every path on customer hosts is content-only.
pub fn content_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/{path:.*}")
            .guard(guard::fn_guard(|ctx| {
                let Some(state) = ctx.app_data::<web::Data<AppState>>() else {
                    return false;
                };
                let Some(raw) = state.config.opts.website_origin.as_deref() else {
                    return false;
                };
                let host = ctx
                    .head()
                    .headers
                    .get(header::HOST)
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("");
                website_host(host, raw).is_some()
            }))
            .to(serve),
    );
}
async fn serve(state: web::Data<AppState>, req: HttpRequest) -> AtomicServerResult<HttpResponse> {
    base_origin(&state)?;
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return Ok(HttpResponse::MethodNotAllowed().finish());
    }
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let id = website_host(host, state.config.opts.website_origin.as_deref().unwrap())
        .unwrap_or_default();
    if id.len() != 40 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(HttpResponse::NotFound().finish());
    }
    let path = req.path().trim_start_matches('/');
    let path = if path.is_empty() || path.ends_with('/') {
        format!("{path}index.html")
    } else {
        path.to_string()
    };
    let mut file = if let Some(versioned) = path.strip_prefix("_releases/") {
        match versioned.split_once('/') {
            Some((version, file)) => {
                state
                    .store
                    .website_public_version_file(&id, version, file)
                    .await?
            }
            None => None,
        }
    } else {
        state.store.website_public_file(&id, &path).await?
    };
    if file.is_none() {
        let (version, asset) = if let Some(rest) = path.strip_prefix("_releases/") {
            rest.split_once('/')
                .map(|(v, p)| (Some(v), p))
                .unwrap_or((None, ""))
        } else {
            (None, path.as_str())
        };
        file = state
            .store
            .website_public_asset(&id, version, asset)
            .await?;
    }
    let Some((deployment, mut bytes)) = file else {
        return Ok(HttpResponse::NotFound()
            .insert_header((header::CACHE_CONTROL, "no-store"))
            .finish());
    };
    // Only the generated runtime URLs are pinned; navigation keeps the website's normal URLs.
    // Inline snapshot data is already part of this exact HTML release.
    if path.ends_with(".html") {
        let html = String::from_utf8(bytes)
            .map_err(|_| AtomicServerError::bad_request("Invalid HTML encoding"))?;
        bytes = html
            .replace(
                "src=\"/assets/",
                &format!("src=\"/_releases/{deployment}/assets/"),
            )
            .replace(
                "src=\"website-runtime.js\"",
                &format!("src=\"/_releases/{deployment}/website-runtime.js\""),
            )
            .replace(
                "data-src=\"search-view.html\"",
                &format!("data-src=\"/_releases/{deployment}/search-view.html\""),
            )
            .into_bytes();
    }
    let mime = if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".webp") {
        "image/webp"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".jpeg") {
        "image/jpeg"
    } else if path.ends_with(".gif") {
        "image/gif"
    } else {
        "text/javascript; charset=utf-8"
    };
    // Revalidate every request so activation/unpublish is visible immediately. No authentication on this host.
    let etag = format!("\"{deployment}\"");
    let unchanged = req
        .headers()
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        == Some(etag.as_str());
    let mut response = if unchanged {
        HttpResponse::NotModified()
    } else {
        HttpResponse::Ok()
    };
    response.insert_header((header::CACHE_CONTROL, "no-cache"))
        .insert_header((header::ETAG, etag))
        .insert_header((header::CONTENT_TYPE, mime))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .insert_header(("Content-Security-Policy", "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-src 'self'; connect-src 'none'; worker-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'self'"));
    Ok(if unchanged || req.method() == Method::HEAD {
        response.finish()
    } else {
        response.body(bytes)
    })
}

#[cfg(all(test, feature = "wasm-plugins"))]
mod tests {
    use super::*;
    use crate::plugins::test_fixture::fixture;
    use actix_web::{test, App};
    fn signed(state: &AppState, path: &str) -> test::TestRequest {
        let url = format!("{}{path}", state.config.get_origin());
        let headers = atomic_lib::client::get_authentication_headers(
            &url,
            &state.store.get_default_agent().unwrap(),
        )
        .unwrap();
        let mut req = test::TestRequest::with_uri(path);
        for (key, value) in headers {
            req = req.insert_header((key, value));
        }
        req
    }
    #[actix_web::test]
    async fn hosting_requires_auth_and_separates_public_content_from_control() {
        let mut f = fixture("website_http").await;
        f.plugin = crate::plugins::test_fixture::genesis(
            &f.appstate.store,
            vec![
                (
                    atomic_lib::urls::PARENT,
                    atomic_lib::Value::AtomicUrl(f.drive.as_str().into()),
                ),
                (
                    atomic_lib::urls::NAME,
                    atomic_lib::Value::String("Website".into()),
                ),
            ],
        )
        .await;
        f.appstate.config.opts.website_origin = Some("http://sites.localhost:9883".into());
        let state = web::Data::new(f.appstate);
        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .configure(content_routes)
                .configure(control_routes)
                .route(
                    "/api-probe",
                    web::get().to(|| async { HttpResponse::Ok().body("private API") }),
                ),
        )
        .await;
        let query = format!(
            "?project={}&drive={}",
            urlencoding::encode(&f.plugin),
            urlencoding::encode(&f.drive)
        );
        let upload = format!("/website-hosting/deployments{query}");
        let status = format!("/website-hosting{query}");
        let activate = format!("/website-hosting/activate{query}");
        let package = serde_json::json!({"version":1,"files":{"index.html":"<h1>Bakery</h1>","menu/index.html":"Menu"}});
        let forbidden = test::call_service(
            &app,
            test::TestRequest::post()
                .uri(&upload)
                .set_json(&package)
                .to_request(),
        )
        .await;
        assert!(!forbidden.status().is_success());
        let result = test::call_service(
            &app,
            signed(&state, &upload)
                .method(Method::POST)
                .set_json(&package)
                .to_request(),
        )
        .await;
        if !result.status().is_success() {
            panic!("upload failed: {:?}", test::read_body(result).await);
        }
        let uploaded: serde_json::Value = test::read_body_json(result).await;
        let id = uploaded["deployment"].as_str().unwrap();
        let host = format!("{}.sites.localhost:9883", project_id(&f.plugin));
        let before = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/")
                .insert_header(("Host", host.clone()))
                .to_request(),
        )
        .await;
        assert_eq!(before.status(), 404);
        let preview = format!("/website-hosting/preview/{id}{query}");
        assert!(
            !test::call_service(&app, test::TestRequest::get().uri(&preview).to_request())
                .await
                .status()
                .is_success()
        );
        let private = test::call_service(&app, signed(&state, &preview).to_request()).await;
        assert_eq!(
            private.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(
            test::read_body_json::<serde_json::Value, _>(private).await,
            package
        );
        let body =
            serde_json::json!({"expectedRevision":uploaded["state"]["revision"],"deployment":id});
        let live = test::call_service(
            &app,
            signed(&state, &activate)
                .method(Method::POST)
                .set_json(&body)
                .to_request(),
        )
        .await;
        assert!(live.status().is_success());
        let live: serde_json::Value = test::read_body_json(live).await;
        let stale = test::call_service(
            &app,
            signed(&state, &activate)
                .method(Method::POST)
                .set_json(&body)
                .to_request(),
        )
        .await;
        assert_eq!(stale.status(), 409);
        let page = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/")
                .insert_header(("Host", host.clone()))
                .to_request(),
        )
        .await;
        assert_eq!(page.status(), 200);
        assert_eq!(test::read_body(page).await, "<h1>Bakery</h1>");
        let nested = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/menu/")
                .insert_header(("Host", host.clone()))
                .to_request(),
        )
        .await;
        assert_eq!(test::read_body(nested).await, "Menu");
        for path in [&status, "/api-probe"] {
            let api = test::call_service(
                &app,
                signed(&state, path)
                    .insert_header(("Host", host.clone()))
                    .to_request(),
            )
            .await;
            assert_eq!(
                api.status(),
                404,
                "Customer hosts must never reach API handlers"
            );
        }
        let disable =
            serde_json::json!({"expectedRevision":live["state"]["revision"],"deployment":null});
        assert!(test::call_service(
            &app,
            signed(&state, &activate)
                .method(Method::POST)
                .set_json(&disable)
                .to_request()
        )
        .await
        .status()
        .is_success());
        assert_eq!(
            test::call_service(
                &app,
                test::TestRequest::get()
                    .uri("/")
                    .insert_header(("Host", host))
                    .to_request()
            )
            .await
            .status(),
            404
        );
        // Passing a writable nested resource as "drive" must not weaken publish authority.
        let wrong = format!(
            "/website-hosting?project={}&drive={}",
            urlencoding::encode(&f.plugin),
            urlencoding::encode(&f.plugin)
        );
        assert!(
            !test::call_service(&app, signed(&state, &wrong).to_request())
                .await
                .status()
                .is_success()
        );
    }
}
