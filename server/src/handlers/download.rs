use crate::{
    appstate::AppState, context::RequestContext, errors::AtomicServerResult,
    helpers::get_client_agent,
};
use actix_web::http::header::{ContentDisposition, DispositionType};
use actix_web::{web, HttpRequest, HttpResponse};
use atomic_lib::storelike::Query;
use atomic_lib::{urls, Resource, Storelike, Subject, Value};

use serde::Deserialize;
use std::collections::HashSet;

#[serde_with::serde_as]
#[serde_with::skip_serializing_none]
#[derive(Deserialize, Debug)]
pub struct DownloadParams {
    pub q: Option<f32>,
    pub w: Option<u32>,
    pub f: Option<String>,
}

/// Downloads the File of the Resource that matches the same URL minus the `/download` path.
#[tracing::instrument(skip(appstate, req))]
pub async fn handle_download(
    path: Option<web::Path<String>>,
    appstate: web::Data<AppState>,
    params: web::Query<DownloadParams>,
    req: actix_web::HttpRequest,
) -> AtomicServerResult<HttpResponse> {
    let headers = req.headers();
    let origin = RequestContext::new(&req, &appstate).origin;
    let store = &appstate.store;

    let subject_path = if let Some(pth) = path {
        format!("/{}", pth)
    } else {
        // There is no end string, so It's the root of the URL, the base URL!
        return Err("Put `/download` in front of an File URL to download it.".into());
    };

    // Content-addressed shortcut: `/download/files/<64-hex>` serves the blob
    // directly from Tree::Blobs without requiring a resource to live at
    // `<origin>/files/<hash>`. Only fires for raw fetches — image-processing
    // params still go through the File-resource path so we can read mimetype.
    if params.q.is_none() && params.w.is_none() && params.f.is_none() {
        if let Some(hash_hex) = subject_path.strip_prefix("/files/") {
            if let Some(bytes) = blob_by_hash_hex(hash_hex, &appstate)? {
                return Ok(user_blob_response("application/octet-stream", bytes));
            }

            // No whole-file blob under this hash: it may be a chunked file whose
            // `internalId` is this hash. Find it and reconstruct from its chunks.
            if let Some(bytes) = chunked_file_by_internal_id(hash_hex, &appstate).await? {
                return Ok(user_blob_response("application/octet-stream", bytes));
            }
        }
    }

    let subject = atomic_lib::Subject::from_raw(&subject_path, None);

    // Support did:ad:blob: subjects directly in /download
    if subject.is_blob_did() {
        if let Some(hash_hex) = subject.blob_hash_hex() {
            if let Some(bytes) = blob_by_hash_hex(hash_hex, &appstate)? {
                return Ok(user_blob_response("application/octet-stream", bytes));
            }
        }
    }

    let resolved_subject = subject.resolve(&origin);

    let for_agent = get_client_agent(headers, &appstate, &resolved_subject).await?;
    tracing::info!("handle_download: {}", resolved_subject);

    let resource = store
        .get_resource_extended(&resolved_subject.into(), false, &for_agent)
        .await?
        .to_single();

    download_file_handler_partial(&resource, &req, &params, &appstate)
}

/// Serves user-uploaded blob bytes as a forced download rather than rendering
/// inline. The stored `mimetype` is attacker-controlled at upload time (e.g.
/// `text/html`, `image/svg+xml`); with no Content-Disposition/nosniff, a
/// browser opening the download link would render an uploaded script
/// same-origin, reading the session cookie and the Agent's private key out of
/// IndexedDB. Forcing `attachment` + `nosniff` closes that off; it doesn't
/// affect legitimate inline use (e.g. `<img>` embedding), since
/// Content-Disposition only governs top-level navigation, not embedded
/// resource fetches.
fn user_blob_response(content_type: impl AsRef<str>, bytes: Vec<u8>) -> HttpResponse {
    HttpResponse::Ok()
        .content_type(content_type.as_ref())
        .insert_header((
            actix_web::http::header::CONTENT_DISPOSITION,
            ContentDisposition {
                disposition: DispositionType::Attachment,
                parameters: vec![],
            },
        ))
        .insert_header((
            actix_web::http::header::HeaderName::from_static("x-content-type-options"),
            actix_web::http::header::HeaderValue::from_static("nosniff"),
        ))
        .body(bytes)
}

/// Look up a blob by its hex-encoded BLAKE3 hash. Returns `None` if the input
/// is not a 64-char hex string or no blob is stored under that hash.
fn blob_by_hash_hex(hash_hex: &str, appstate: &AppState) -> AtomicServerResult<Option<Vec<u8>>> {
    if hash_hex.len() != 64 {
        return Ok(None);
    }
    let Ok(hash_bytes) = hex::decode(hash_hex) else {
        return Ok(None);
    };
    Ok(appstate
        .store
        .kv
        .get(atomic_lib::db::trees::Tree::Blobs, &hash_bytes)
        .ok()
        .flatten())
}

/// The bytes of a File: concatenated chunk blobs when it is chunked (its `chunks`
/// property is a non-empty ordered list of `did:ad:blob:` refs), otherwise the
/// single blob referenced by `internalId`.
fn reconstruct_file_bytes(resource: &Resource, appstate: &AppState) -> AtomicServerResult<Vec<u8>> {
    if let Ok(Value::ResourceArray(chunks)) = resource.get(urls::CHUNKS) {
        if !chunks.is_empty() {
            let mut out = Vec::new();

            for chunk in chunks {
                let did = chunk.to_string();
                let subject = Subject::from(did.as_str());
                let hash_hex = subject
                    .blob_hash_hex()
                    .ok_or_else(|| format!("Invalid chunk reference: {did}"))?;
                let bytes = blob_by_hash_hex(hash_hex, appstate)?
                    .ok_or_else(|| format!("Chunk blob not found: {hash_hex}"))?;
                out.extend_from_slice(&bytes);
            }

            return Ok(out);
        }
    }

    let internal_id = resource
        .get(urls::INTERNAL_ID)
        .map_err(|e| format!("Internal ID of file could not be resolved. {}", e))?
        .to_string();
    let hash_bytes = hex::decode(&internal_id)
        .map_err(|_| format!("File internalId is not hex: {}", internal_id))?;
    if hash_bytes.len() != 32 {
        return Err(format!(
            "File internalId is not a 32-byte BLAKE3 hash: {}",
            internal_id
        )
        .into());
    }

    appstate
        .store
        .kv
        .get(atomic_lib::db::trees::Tree::Blobs, &hash_bytes)?
        .ok_or_else(|| format!("Blob not found: {}", internal_id).into())
}

/// Find a chunked File by its whole-file `internalId` and reconstruct its bytes,
/// so the content-addressed `/download/files/{hash}` URL works for chunked files
/// (whose whole-file blob is never stored). `None` if no such chunked File.
async fn chunked_file_by_internal_id(
    hash_hex: &str,
    appstate: &AppState,
) -> AtomicServerResult<Option<Vec<u8>>> {
    let result = appstate
        .store
        .query(&Query::new_prop_val(urls::INTERNAL_ID, hash_hex))
        .await?;

    for resource in result.resources {
        if matches!(resource.get(urls::CHUNKS), Ok(Value::ResourceArray(c)) if !c.is_empty()) {
            return Ok(Some(reconstruct_file_bytes(&resource, appstate)?));
        }
    }

    Ok(None)
}

pub fn download_file_handler_partial(
    resource: &Resource,
    _req: &HttpRequest,
    params: &web::Query<DownloadParams>,
    appstate: &AppState,
) -> AtomicServerResult<HttpResponse> {
    let bytes = reconstruct_file_bytes(resource, appstate)?;

    // The source hash for the image-rendition cache key is the whole-file hash.
    let internal_id = resource
        .get(urls::INTERNAL_ID)
        .map(|v| v.to_string())
        .unwrap_or_default();
    let hash_bytes = hex::decode(&internal_id).unwrap_or_default();

    let mimetype = resource
        .get(urls::MIMETYPE)
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "application/octet-stream".to_string());

    // No params: serve the original bytes verbatim.
    if params.q.is_none() && params.w.is_none() && params.f.is_none() {
        return Ok(user_blob_response(mimetype, bytes));
    }

    // With image params: serve a processed rendition. Cache it in Tree::Blobs
    // under a deterministic synthetic hash so future requests with the same
    // params hit the cache and any peer that has produced the same rendition
    // can serve it content-addressably.
    serve_processed_image(&bytes, &hash_bytes, params, appstate)
}

#[cfg(feature = "img")]
fn serve_processed_image(
    source_bytes: &[u8],
    source_hash: &[u8],
    params: &web::Query<DownloadParams>,
    appstate: &AppState,
) -> AtomicServerResult<HttpResponse> {
    use crate::handlers::image::{is_image_bytes, process_image_bytes};

    let quantized = quantize_params(params);
    let params = &quantized;
    let format = get_format(params)?;
    let cache_key = processed_cache_key(source_hash, &format, params);

    if let Some(cached) = appstate
        .store
        .kv
        .get(atomic_lib::db::trees::Tree::Blobs, &cache_key)?
    {
        return Ok(user_blob_response(mimetype_for(&format), cached));
    }

    if !is_image_bytes(source_bytes) {
        return Err("Quality or width parameters are only supported for image files".into());
    }

    let encoded = process_image_bytes(source_bytes, params, &format)?;
    appstate
        .store
        .kv
        .insert(atomic_lib::db::trees::Tree::Blobs, &cache_key, &encoded)?;

    Ok(user_blob_response(mimetype_for(&format), encoded))
}

#[cfg(not(feature = "img"))]
fn serve_processed_image(
    _source_bytes: &[u8],
    _source_hash: &[u8],
    _params: &web::Query<DownloadParams>,
    _appstate: &AppState,
) -> AtomicServerResult<HttpResponse> {
    Err("Image processing is not enabled in this build (compile with the `img` feature)".into())
}

/// Deterministic 32-byte cache key for a processed rendition. Same source
/// hash + same params => same key on every server, so the rendition is
/// content-addressable across the mesh.
fn processed_cache_key(source_hash: &[u8], format: &str, params: &DownloadParams) -> [u8; 32] {
    let canonical = format!(
        "processed|hash={}|f={}|q={}|w={}",
        hex::encode(source_hash),
        format,
        params.q.map(|q| q.to_string()).unwrap_or_default(),
        params.w.map(|w| w.to_string()).unwrap_or_default(),
    );
    *blake3::hash(canonical.as_bytes()).as_bytes()
}

/// Largest width a rendition is produced at; wider requests are clamped.
#[cfg(feature = "img")]
const MAX_RENDITION_WIDTH: u32 = 4096;
/// Widths are rounded up to a multiple of this, qualities to whole numbers.
#[cfg(feature = "img")]
const RENDITION_WIDTH_STEP: u32 = 64;

/// Snap the rendition parameters onto a small grid before they reach either
/// the encoder or the cache key. Renditions are persisted per distinct
/// parameter set and nothing evicts them, so with `q` an `f32` and `w` any
/// number, a reader of one public image could grow the store without bound by
/// varying them. On the grid there are at most 100 x 64 renditions per format.
#[cfg(feature = "img")]
fn quantize_params(params: &DownloadParams) -> DownloadParams {
    let q = params.q.map(|q| {
        let q = if q.is_finite() { q } else { 80.0 };
        q.round().clamp(1.0, 100.0)
    });
    let w = params.w.map(|w| {
        let w = w.clamp(1, MAX_RENDITION_WIDTH);
        w.div_ceil(RENDITION_WIDTH_STEP) * RENDITION_WIDTH_STEP
    });
    DownloadParams {
        q,
        w,
        f: params.f.clone(),
    }
}

fn mimetype_for(format: &str) -> &'static str {
    match format {
        "webp" => "image/webp",
        "avif" => "image/avif",
        _ => "application/octet-stream",
    }
}

fn get_format(params: &DownloadParams) -> AtomicServerResult<String> {
    let supported_compression_formats: HashSet<String> =
        HashSet::from_iter(vec!["webp".to_string(), "avif".to_string()]);

    let format = params.f.clone().unwrap_or("webp".to_string());
    if !supported_compression_formats.contains(&format) {
        return Err("Unsupported format".into());
    }

    Ok(format)
}
