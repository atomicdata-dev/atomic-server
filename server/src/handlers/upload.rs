use std::{ffi::OsStr, path::Path};

use actix_multipart::{Field, Multipart};
use actix_web::{web, HttpResponse};
use atomic_lib::{hierarchy::check_write, urls, Db, Resource, Storelike, Subject, Value};
use futures::{StreamExt, TryStreamExt};
#[cfg(feature = "img")]
use image::GenericImageView;
use serde::Deserialize;

use crate::{appstate::AppState, errors::AtomicServerResult, helpers::get_client_agent};

#[derive(Deserialize, Debug)]
pub struct UploadQuery {
    parent: String,
}

/// Allows the user to upload files tot the `/upload` endpoint.
/// A parent Query parameter is required for checking rights and for placing the file in a Hierarchy.
/// Creates new File resources for every submitted file.
/// Submission is done using multipart/form-data.
/// The file is stored in the `/uploads` directory.
#[tracing::instrument(skip(appstate, req, body))]
pub async fn upload_handler(
    mut body: Multipart,
    appstate: web::Data<AppState>,
    query: web::Query<UploadQuery>,
    req: actix_web::HttpRequest,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    let origin = context.origin.clone();
    let store = &appstate.store;

    let parent = store.get_resource(&query.parent.clone().into()).await?;
    let path_and_query = req
        .head()
        .uri
        .path_and_query()
        .ok_or("Path must be given")?
        .to_string();
    let subject = atomic_lib::Subject::from_raw(&path_and_query, None).resolve(&origin);
    let agent = get_client_agent(req.headers(), &appstate, &subject).await?;
    check_write(store, &parent, &agent).await?;

    let mut created_resources: Vec<Resource> = Vec::new();

    while let Ok(Some(field)) = body.try_next().await {
        let mut resource =
            save_file_and_create_resource(field, &appstate, &query.parent, store, &origin).await?;
        resource.save(store).await?;
        created_resources.push(resource);
    }

    let mut builder = HttpResponse::Ok();

    Ok(builder.body(atomic_lib::serialize::resources_to_json_ad(
        &created_resources,
        &origin,
        true,
    )?))
}

async fn save_file_and_create_resource(
    mut field: Field,
    _appstate: &web::Data<AppState>,
    parent: &str,
    store: &Db,
    // The full origin URL (e.g., "https://example.com") for constructing resource subjects
    origin: &str,
) -> AtomicServerResult<Resource> {
    let content_type = field
        .content_disposition()
        .ok_or("Content-Disposition header is missing")?;
    let filename = content_type
        .get_filename()
        .ok_or("Filename is missing")?
        .to_string();

    let mut hasher = blake3::Hasher::new();
    let mut buffer = Vec::new();

    // Field in turn is stream of *Bytes* object
    while let Some(chunk) = field.next().await {
        let data = chunk.map_err(|e| format!("Error while reading multipart data. {}", e))?;
        // `PayloadConfig` only bounds the `Bytes`/`String` extractors, not a
        // multipart stream read by hand, so bound it here.
        if buffer.len() + data.len() > crate::serve::PAYLOAD_MAX {
            return Err(format!(
                "Uploaded file exceeds the maximum size of {} bytes",
                crate::serve::PAYLOAD_MAX
            )
            .into());
        }
        hasher.update(&data);
        buffer.extend_from_slice(&data);
    }

    let hash = hasher.finalize();
    let hash_str = hash.to_hex().to_string();
    let hash_bytes = hash.as_bytes();

    // Bytes are stored content-addressed in Tree::Blobs. The capability to
    // fetch them is the hash itself; no filesystem copy is needed. See
    // docs/src/files.md.
    store
        .kv
        .insert(atomic_lib::db::trees::Tree::Blobs, hash_bytes, &buffer)?;

    let byte_count: i64 = buffer.len() as i64;

    let mimetype = guess_mime_for_filename(&filename);
    let subject_path = format!("files/{}", urlencoding::encode(&hash_str));
    // Build a proper Internal subject using Subject::new_local so that
    // Resource::save correctly identifies this as a local resource and applies
    // the commit in-process (instead of POSTing via HTTP, which fails with
    // "Incorrect signature" because of serialization differences).
    let subject = Subject::new_local(&format!("/{}", subject_path), None);
    let download_url = format!("{}/download/{}", origin, subject_path);

    let mut resource = atomic_lib::Resource::new_instance(urls::FILE, store).await?;
    resource
        .set_subject(subject.to_string())
        .set_string(urls::PARENT.into(), parent, store)
        .await?
        .set_string(urls::INTERNAL_ID.into(), &hash_str, store)
        .await?
        .set(
            urls::BLOB.into(),
            Value::AtomicUrl(format!("did:ad:blob:{}", hash_str).into()),
            store,
        )
        .await?
        .set(urls::FILESIZE.into(), Value::Integer(byte_count), store)
        .await?
        .set_string(urls::MIMETYPE.into(), &mimetype, store)
        .await?
        .set_string(urls::FILENAME.into(), &filename, store)
        .await?
        .set_string(urls::DOWNLOAD_URL.into(), &download_url, store)
        .await?;

    #[cfg(feature = "img")]
    if mimetype.starts_with("image/") {
        if let Ok(img) = image::load_from_memory(&buffer) {
            let (width, height) = img.dimensions();
            resource
                .set(
                    urls::IMAGE_WIDTH.into(),
                    Value::Integer(width as i64),
                    store,
                )
                .await?
                .set(
                    urls::IMAGE_HEIGHT.into(),
                    Value::Integer(height as i64),
                    store,
                )
                .await?;
        }
    }

    Ok(resource)
}

fn guess_mime_for_filename(filename: &str) -> String {
    if let Some(ext) = get_extension_from_filename(filename) {
        actix_files::file_extension_to_mime(ext).to_string()
    } else {
        "application/octet-stream".to_string()
    }
}

fn get_extension_from_filename(filename: &str) -> Option<&str> {
    Path::new(filename).extension().and_then(OsStr::to_str)
}
