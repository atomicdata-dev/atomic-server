//! Publish releases and serve them.
//!
//! Three ways in, one path through: a JS draft (`/plugin-release`, public, and
//! `/plugin-release-pin`, private), and a zip (`/plugin-release-package`). Each
//! handler only builds the `PluginRelease`; recording it, listing it and
//! checking the world live in `plugins::release`.
use crate::{
    appstate::AppState,
    context::RequestContext,
    errors::{AtomicServerError, AtomicServerResult},
    plugins::{
        js_runtime,
        release::{self, ListingInput, Published},
    },
};
use actix_web::{web, HttpResponse};
use atomic_lib::{
    agents::ForAgent, db::plugin_release::PluginRelease, hierarchy::check_read, storelike::Query,
    urls, Storelike, Value,
};

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Publish {
    pub drive: String,
    pub plugin: String,
    #[serde(default)]
    pub schemas: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub standards: Vec<String>,
}

/// Publishes a JS draft as a release and lists it in this server's marketplace.
pub async fn publish(
    appstate: web::Data<AppState>,
    body: web::Json<Publish>,
    req: actix_web::HttpRequest,
    context: RequestContext,
) -> AtomicServerResult<HttpResponse> {
    from_draft(appstate, body, req, context, true).await
}

/// Publishes a JS draft as a private release, so a connection can pin it.
pub async fn pin(
    appstate: web::Data<AppState>,
    body: web::Json<Publish>,
    req: actix_web::HttpRequest,
    context: RequestContext,
) -> AtomicServerResult<HttpResponse> {
    from_draft(appstate, body, req, context, false).await
}

async fn from_draft(
    appstate: web::Data<AppState>,
    body: web::Json<Publish>,
    req: actix_web::HttpRequest,
    context: RequestContext,
    public: bool,
) -> AtomicServerResult<HttpResponse> {
    let agent = super::plugin_schedule::authorize(&appstate, &req, &context, &body.plugin).await?;
    let store = &appstate.store;
    let source = crate::plugins::scheduler::plugin_source(store, &body.drive, &body.plugin)
        .await
        .ok_or_else(|| AtomicServerError::bad_request("Plugin has no source"))?;
    let manifest = js_runtime::describe_manifest(&source)
        .await?
        .ok_or_else(|| {
            AtomicServerError::bad_request("Published releases require a versioned manifest")
        })?;
    js_runtime::StoreHost::bound(
        store,
        &body.drive,
        &body.plugin,
        agent.clone(),
        Some(manifest.clone()),
    )
    .await?;
    let schemas = match &body.schemas {
        Some(schemas) => schemas.clone(),
        None => {
            crate::plugins::scheduler::plugin_schema_bindings(store, &body.drive, &body.plugin)
                .await?
        }
    };
    for subject in schemas.values() {
        let resource = store.get_resource(&subject.as_str().into()).await?;
        check_read(store, &resource, &agent).await?;
    }
    let release = PluginRelease::js(source, serde_json::json!(manifest), schemas);
    let listing = if public {
        let draft = store.get_resource(&body.plugin.as_str().into()).await?;
        let text = |prop: &str| draft.get(prop).ok().map(|v| v.to_string());
        Some(ListingInput {
            name: text(urls::NAME).unwrap_or_else(|| "Plugin".into()),
            emoji: text(urls::EMOJI),
            description: text(urls::DESCRIPTION).unwrap_or_default(),
            domains: body.domains.clone(),
            standards: body.standards.clone(),
        })
    } else {
        None
    };
    respond(&appstate, &context, &release, &body.drive, &agent, listing).await
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublishPackage {
    /// The drive the publisher must be able to write to.
    pub drive: String,
    /// What the publisher believes the world is. The world is read from the
    /// component (a package extending classes is a `server-extension`); when
    /// this is given and disagrees, the publish is refused rather than
    /// mislabeled, before anything is stored.
    #[serde(default)]
    pub world: Option<String>,
    /// Also list the release in this server's marketplace.
    #[serde(default)]
    pub public: bool,
}

/// Publishes a wasip2 release from zip bytes: the body is the zip, validated
/// like an upload, its `plugin.json` translated into the version-two manifest,
/// stored content-addressed, and wrapped in a release whose id covers the
/// package hash and manifest. `atomic-plugin` can publish with one POST
/// instead of producing a file to upload.
pub async fn publish_package(
    appstate: web::Data<AppState>,
    query: web::Query<PublishPackage>,
    body: web::Bytes,
    req: actix_web::HttpRequest,
    context: RequestContext,
) -> AtomicServerResult<HttpResponse> {
    let agent = super::plugin_schedule::authorize(&appstate, &req, &context, &query.drive).await?;
    // The claimed world goes in, so a package that does not match it is
    // refused before its bytes or its release record are stored.
    let (_, release, manifest) =
        release::publish_package(&appstate.store, &body, query.world.as_deref())
            .await
            .map_err(|e| AtomicServerError::bad_request(e.to_string()))?;
    let listing = query.public.then(|| ListingInput::from_manifest(&manifest));
    respond(&appstate, &context, &release, &query.drive, &agent, listing).await
}

/// Records the release (and its Listing) under the publisher's drive and
/// answers with the id, the `Release` URL an Installation can point at, the
/// `Listing` URL when public, and the release itself.
async fn respond(
    appstate: &AppState,
    context: &RequestContext,
    release: &PluginRelease,
    drive: &str,
    agent: &ForAgent,
    listing: Option<ListingInput>,
) -> AtomicServerResult<HttpResponse> {
    let publisher = match agent {
        ForAgent::AgentSubject(subject) => Some(subject.to_string()),
        _ => None,
    };
    let Published {
        id,
        subject,
        listing,
    } = release::publish_release(
        &appstate.store,
        release,
        drive,
        publisher.as_deref(),
        &context.origin,
        listing,
    )
    .await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": id,
        "subject": subject.resolve(&context.origin),
        "listing": listing.map(|l| l.resolve(&context.origin)),
        "release": release,
    })))
}

/// This server's marketplace: every `Listing` the public can read, as a JSON
/// array. Private releases have no Listing and are absent.
///
/// Each entry has:
/// - `subject`: the Listing resource URL
/// - `name`, `emoji` (nullable), `description`
/// - `publisher`: the publishing Agent's URL, or null
/// - `domains`: array of strings; `standards`: array of documentation URLs
/// - `release`: the `Release` resource URL an Installation pins
/// - `releaseId`: the `blake3:` id, also what `/plugin-package/{id}` takes
/// - `runtime` (`atomic-js/1` | `wasip2/1`) and `world` (`extension` |
///   `server-extension`), from the release; null when it is not in this
///   node's cache
pub async fn catalog(appstate: web::Data<AppState>) -> AtomicServerResult<HttpResponse> {
    let store = &appstate.store;
    let listings = store
        .query(&Query {
            property: Some(urls::IS_A.into()),
            value: Some(Value::AtomicUrl(urls::LISTING.into())),
            include_nested: true,
            for_agent: ForAgent::Public,
            ..Default::default()
        })
        .await?;
    let origin = store.get_server_url();
    let entries: Vec<serde_json::Value> = listings
        .resources
        .iter()
        .map(|listing| {
            let text = |prop: &str| listing.get(prop).ok().map(|v| v.to_string());
            let json = |prop: &str| match listing.get(prop) {
                Ok(Value::Json(v)) => v.clone(),
                Ok(Value::ResourceArray(items)) => {
                    serde_json::json!(items.iter().map(|i| i.to_string()).collect::<Vec<_>>())
                }
                Ok(other) => serde_json::from_str(&other.to_string())
                    .unwrap_or(serde_json::Value::Array(vec![])),
                Err(_) => serde_json::Value::Array(vec![]),
            };
            let release_id = text(urls::RELEASE_ID);
            let cached = release_id
                .as_deref()
                .and_then(|id| store.get_plugin_release(id).ok());
            serde_json::json!({
                "subject": listing.get_subject().resolve(&origin),
                "name": text(urls::NAME),
                "emoji": text(urls::EMOJI),
                "description": text(urls::DESCRIPTION).unwrap_or_default(),
                "publisher": text(urls::PUBLISHER),
                "domains": json(urls::DOMAINS),
                "standards": json(urls::STANDARDS),
                "release": text(urls::RELEASE_PROP),
                "releaseId": release_id,
                "runtime": cached.as_ref().map(|r| r.runtime.clone()),
                "world": cached.as_ref().map(|r| r.world.clone()),
            })
        })
        .collect();
    Ok(HttpResponse::Ok().json(entries))
}

/// A release the caller may see: one listed in this server's marketplace, or a
/// private one whose `Release` resource the signing agent can read (its
/// publisher's drive), so an Installation view can re-fetch the manifest and
/// runtime it pinned. The read check is the resource's own; there is no
/// separate rule for releases.
async fn readable_release(
    appstate: &AppState,
    req: &actix_web::HttpRequest,
    context: &RequestContext,
    id: &str,
) -> AtomicServerResult<PluginRelease> {
    let store = &appstate.store;
    if release::is_listed(store, id).await {
        return Ok(store.get_plugin_release(id)?);
    }
    let subject = release::release_subject(id);
    let Ok(resource) = store.get_resource(&subject).await else {
        return Err(AtomicServerError::bad_request(
            "This package has not been published",
        ));
    };
    let path_and_query = req
        .head()
        .uri
        .path_and_query()
        .ok_or("Path must be given")?
        .to_string();
    let signed_subject =
        atomic_lib::Subject::from_raw(&path_and_query, None).resolve(&context.origin);
    let agent = crate::helpers::get_client_agent(req.headers(), appstate, &signed_subject).await?;
    check_read(store, &resource, &agent).await?;
    Ok(store.get_plugin_release(id)?)
}

/// The release record: source for JS releases, the `package` hash (never the
/// bytes) for wasip2 releases, which `GET /plugin-package/{id}/zip` serves.
pub async fn package(
    appstate: web::Data<AppState>,
    id: web::Path<String>,
    req: actix_web::HttpRequest,
    context: RequestContext,
) -> AtomicServerResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(readable_release(&appstate, &req, &context, &id).await?))
}

/// The zip of a published wasip2 release, byte for byte what was published,
/// so a client can verify it against the release's `package` hash.
pub async fn package_zip(
    appstate: web::Data<AppState>,
    id: web::Path<String>,
    req: actix_web::HttpRequest,
    context: RequestContext,
) -> AtomicServerResult<HttpResponse> {
    let release = readable_release(&appstate, &req, &context, &id).await?;
    let Some(package) = release.package.as_deref() else {
        return Err(AtomicServerError::bad_request(
            "This release is a JS release; it has no package",
        ));
    };
    let bytes = release::package_bytes(&appstate.store, package).await?;
    Ok(HttpResponse::Ok()
        .content_type("application/zip")
        .insert_header(("Cache-Control", "public, max-age=31536000, immutable"))
        .body(bytes))
}
