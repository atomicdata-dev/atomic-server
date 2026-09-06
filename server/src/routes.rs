//! Contains routing logic, sends the client to the correct handler.
//! We should try to minimize what happens in here, since most logic should be defined in Atomic Data - not in the server itself.

use crate::{content_types, handlers};
use actix_web::{
    guard,
    http::{header, Method},
    web, HttpRequest, HttpResponse,
};
use actix_web_static_files::ResourceFiles;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Should match all routes
const ANY: &str = "{tail:.*}";

// Includes the js assets from the `browser` folder,
// used for hosting the front-end JS bundles, service workers,
// css, icons and other static files.
// See build.rs for more info.
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// Lightweight index of the embedded resource map, computed once.
/// `static_files::Resource` is not `Clone`, so we can't cache the whole
/// HashMap in a `OnceLock` and pass it to `ResourceFiles` too —
/// instead we mirror just the fields the precompressed-asset handler
/// reads (data + mime type), keyed by path. `ResourceFiles::new` calls
/// `generate()` again at startup; that allocation only happens once
/// per worker, not per request.
fn precompressed_index() -> &'static HashMap<&'static str, (&'static [u8], &'static str)> {
    static INDEX: OnceLock<HashMap<&'static str, (&'static [u8], &'static str)>> = OnceLock::new();
    INDEX.get_or_init(|| {
        generate()
            .into_iter()
            .map(|(k, v)| (k, (v.data, v.mime_type)))
            .collect()
    })
}

/// Serve a pre-compressed `.br` asset when the request supports brotli
/// AND a precompressed sibling exists in the embedded resource map.
/// The build script (`build.rs`) writes these at brotli q11, which is
/// considerably tighter than actix's runtime `Compress` middleware
/// (default q ~ 3). For the Loro WASM this is ~250 KB on the wire saved.
///
/// This handler is mounted BEFORE `ResourceFiles` with a guard that
/// only matches when the precompressed file is actually available, so
/// requests for non-precompressed paths (or clients that don't accept
/// brotli) fall through to the normal asset handler.
async fn serve_precompressed_br(req: HttpRequest) -> HttpResponse {
    let path = req.uri().path().trim_start_matches('/');
    let map = precompressed_index();
    let br_key: String = format!("{}.br", path);
    let (Some((br_data, _)), Some((_, mime))) = (map.get(br_key.as_str()), map.get(path)) else {
        return HttpResponse::NotFound().finish();
    };
    HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, *mime))
        .insert_header((header::CONTENT_ENCODING, "br"))
        .insert_header((header::VARY, "Accept-Encoding"))
        .body(*br_data)
}

/// Guard that passes when the request both accepts brotli AND there is a
/// precompressed `<path>.br` available in the embedded resource map.
fn precompressed_br_available(ctx: &guard::GuardContext<'_>) -> bool {
    let head = ctx.head();
    let accepts_br = head
        .headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|enc| enc.trim().starts_with("br")));
    if !accepts_br {
        return false;
    }
    let path = head.uri.path().trim_start_matches('/');
    let map = precompressed_index();
    let br_key = format!("{}.br", path);
    map.contains_key(br_key.as_str()) && map.contains_key(path)
}

fn node_id_from_did(node_did: &str) -> Result<&str, &'static str> {
    let Some(rest) = node_did.strip_prefix("did:ad:node:") else {
        return Err("Expected nodeId to use did:ad:node:<node-id>");
    };
    let node_id = rest.split(':').next().unwrap_or(rest);
    if node_id.is_empty() {
        return Err("Expected nodeId to include a node id");
    }
    if node_id.len() != 64 || !node_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Expected nodeId to include a 64-character hex node id");
    }

    Ok(node_id)
}

/// POST /iroh-sync { "nodeId": "did:ad:node:<node-id>", "drive": "..." }
/// Triggers an Iroh peer sync from the server to the given Node DID.
async fn iroh_sync_handler(
    body: web::Json<serde_json::Value>,
    appstate: web::Data<crate::appstate::AppState>,
) -> actix_web::HttpResponse {
    let node_id = match body.get("nodeId").and_then(|v| v.as_str()) {
        Some(id) => match node_id_from_did(id) {
            Ok(node_id) => node_id,
            Err(error) => {
                return actix_web::HttpResponse::BadRequest()
                    .json(serde_json::json!({"error": error}));
            }
        },
        None => {
            return actix_web::HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "Missing nodeId"}));
        }
    };
    let drive = match body.get("drive").and_then(|v| v.as_str()) {
        Some(d) => d,
        None => {
            return actix_web::HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "Missing drive"}));
        }
    };

    match atomic_lib::sync::peer::sync_drive_with_peer_outcome(node_id, drive, &appstate.store)
        .await
    {
        Ok(outcome) => actix_web::HttpResponse::Ok().json(serde_json::json!({
            "count": outcome.count,
            // Both directions. Reporting only `count` (what we pulled) made a
            // pass that pushed 49 resources and pulled 1 read as
            // "Synced 1 resource" — the user cannot tell a working sync from a
            // stalled one if the number only describes half of it.
            "pushed": outcome.pushed,
            // `peerName` is the remote's self-reported `HELLO` label.
            // Older peers that don't speak HELLO yet send `null`; the UI
            // falls back to a truncated Node DID in that case.
            "peerName": outcome.peer_name,
            "status": "ok",
        })),
        Err(e) => actix_web::HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": e.to_string()})),
    }
}

#[cfg(test)]
mod node_id_tests {
    use super::node_id_from_did;

    #[test]
    fn accepts_node_did() {
        let node_id = "a".repeat(64);
        assert_eq!(
            node_id_from_did(&format!("did:ad:node:{node_id}")).unwrap(),
            node_id
        );
    }

    #[test]
    fn accepts_node_did_with_label_suffix() {
        let node_id = "a".repeat(64);
        assert_eq!(
            node_id_from_did(&format!("did:ad:node:{node_id}:Joe%27s%20Tablet")).unwrap(),
            node_id
        );
    }

    #[test]
    fn rejects_iroh_prefix() {
        assert!(node_id_from_did("iroh:abcdef").is_err());
    }

    #[test]
    fn rejects_raw_node_id() {
        assert!(node_id_from_did(&"a".repeat(64)).is_err());
    }

    #[test]
    fn rejects_invalid_node_id() {
        assert!(node_id_from_did("did:ad:node:not-a-node").is_err());
    }
}

/// Set up the Actix server routes. This defines which paths are used.
// Keep in mind that the order of these matters. An early, greedy route will take
// precedence over a later route.
pub fn config_routes(app: &mut actix_web::web::ServiceConfig) {
    app.service(
        web::resource("/upload")
            .guard(guard::Method(Method::POST))
            .to(handlers::upload::upload_handler),
    )
    .service(
        web::resource("/commit")
            .guard(guard::Method(Method::POST))
            .to(handlers::commit::post_commit),
    )
    .service(web::resource("/download/{path:[^{}]+}").to(handlers::download::handle_download))
    .service(
        web::resource("/blob/{hash}")
            .guard(guard::Method(Method::PUT))
            .to(handlers::blob::put_blob),
    )
    .service(
        web::resource("/bind-drive")
            .guard(guard::Method(Method::POST))
            .to(handlers::post_resource::handle_post_resource),
    )
    .service(web::resource("/ws").to(handlers::web_sockets::web_socket_handler))
    .service(web::resource("/drive-usage").to(handlers::drive_usage::handle_drive_usage))
    .service(
        web::resource("/history-attribution")
            .to(handlers::history_attribution::handle_history_attribution),
    )
    .service(
        web::resource("/forget-peer")
            .guard(guard::Method(Method::POST))
            .to(handlers::forget_peer::handle_forget_peer),
    )
    .service(web::resource("/iroh-sync").to(iroh_sync_handler))
    .service(web::resource("/export").to(handlers::export::handle_export))
    .service(web::resource("/plugin-ui").to(handlers::plugin_ui::handle_plugin_ui))
    .service(web::resource("/plugin-list").to(handlers::plugin_ui::handle_plugin_list))
    // Serve pre-compressed brotli assets when:
    //   - The client sends `Accept-Encoding: br`, AND
    //   - The build script wrote a `<path>.br` sibling into the
    //     embedded resource map (see `build.rs::precompress_assets`).
    // The guard short-circuits this service when either condition is
    // missing, so the request falls through to the normal
    // `ResourceFiles` handler below — which then serves the original
    // (and gets compressed at runtime by `middleware::Compress` if
    // applicable). Must be registered BEFORE `ResourceFiles` so that
    // ResourceFiles' own `skip_handler_when_not_found` guard doesn't
    // claim the request first.
    .service(
        web::resource(ANY)
            .guard(guard::Method(Method::GET))
            .guard(guard::fn_guard(precompressed_br_available))
            .to(serve_precompressed_br),
    )
    // This `generate` imports the static files from the `app_assets` folder
    .service(
        ResourceFiles::new("/", generate())
            .skip_handler_when_not_found()
            .do_not_resolve_defaults(),
    )
    // Catch all (non-download) HTML requests and send them to the single page app
    .service(
        web::resource(ANY)
            .guard(guard::Method(Method::GET))
            .guard(guard::fn_guard(|guard_ctx| {
                content_types::get_accept(guard_ctx.head().headers())
                    == content_types::ContentType::Html
            }))
            .to(handlers::single_page_app::single_page),
    )
    .service(
        web::resource("/search")
            .guard(guard::Method(Method::GET))
            .to(handlers::search::search_query),
    );
    #[cfg(feature = "vector-search")]
    app.service(
        web::resource("/vector_search")
            .guard(guard::Method(Method::GET))
            .to(handlers::vector_search::vector_search_query),
    );
    app.service(
        web::resource(ANY)
            .guard(guard::Method(Method::POST))
            .to(handlers::post_resource::handle_post_resource),
    )
    .service(
        web::resource(ANY)
            .guard(guard::Method(Method::GET))
            .to(handlers::get_resource::handle_get_resource),
    )
    // Also allow the home resource (not matched by the previous one)
    .service(web::resource("/").to(handlers::get_resource::handle_get_resource));
}
