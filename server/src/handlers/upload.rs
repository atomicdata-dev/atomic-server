use std::{ffi::OsStr, io::Write, path::Path};

use actix_multipart::Multipart;
use actix_web::{web, HttpResponse};
use atomic_lib::{
    commit::CommitResponse, hierarchy::check_write, urls, utils::now, Resource, Storelike, Value,
};
use futures::{StreamExt, TryStreamExt};
use serde::Deserialize;

use crate::{
    appstate::AppState,
    errors::AtomicServerResult,
    helpers::{get_client_agent, get_subject},
};

#[derive(Deserialize, Debug)]
pub struct UploadQuery {
    parent: String,
}

/// Allows the user to upload files tot the `/upload` endpoint.
/// A parent Query parameter is required for checking rights and for placing the file in a Hierarchy.
/// Creates new File resources for every submitted file.
/// Submission is done using multipart/form-data.
/// The file is stored in the `/uploads` directory.
/// An `attachment` relationship is created from the parent
#[tracing::instrument(skip(appstate, req, body))]
pub async fn upload_handler(
    mut body: Multipart,
    appstate: web::Data<AppState>,
    query: web::Query<UploadQuery>,
    req: actix_web::HttpRequest,
    conn: actix_web::dev::ConnectionInfo,
) -> AtomicServerResult<HttpResponse> {
    let store = &appstate.store;
    let parent = store.get_resource(&query.parent)?;
    let subject = get_subject(&req, &conn, &appstate)?;
    let for_agent = get_client_agent(req.headers(), &appstate, subject)?;
    check_write(store, &parent, &for_agent)?;

    let mut created_resources: Vec<Resource> = Vec::new();
    let mut commit_responses: Vec<CommitResponse> = Vec::new();

    while let Ok(Some(mut field)) = body.try_next().await {
        let content_type = field.content_disposition().clone();
        let filename = content_type.get_filename().ok_or("Filename is missing")?;

        std::fs::create_dir_all(&appstate.config.uploads_path)?;

        let file_id = format!(
            "{}-{}",
            now(),
            sanitize_filename::sanitize(filename)
                // Spacebars lead to very annoying bugs in browsers
                .replace(' ', "-")
        );

        let mut file_path = appstate.config.uploads_path.clone();
        file_path.push(&file_id);
        let mut file = std::fs::File::create(file_path)?;

        // Field in turn is stream of *Bytes* object
        while let Some(chunk) = field.next().await {
            let data = chunk.map_err(|e| format!("Error while reading multipart data. {}", e))?;
            // TODO: Update a SHA256 hash here for checksum
            file.write_all(&data)?;
        }

        let byte_count: i64 = file
            .metadata()?
            .len()
            .try_into()
            .map_err(|_e| "Too large")?;

        let subject_path = format!("files/{}", urlencoding::encode(&file_id));
        let new_subject = store
            .get_server_url()
            .clone()
            .set_path(&subject_path)
            .to_string();
        let download_url = store
            .get_server_url()
            .clone()
            .set_path(&format!("download/{}", subject_path))
            .to_string();

        let mut resource = atomic_lib::Resource::new_instance(urls::FILE, store)?;
        resource.set_subject(new_subject);
        resource.set_propval_string(urls::PARENT.into(), &query.parent, store)?;
        resource.set_propval_string(urls::INTERNAL_ID.into(), &file_id, store)?;
        resource.set_propval(urls::FILESIZE.into(), Value::Integer(byte_count), store)?;
        resource.set_propval_string(
            urls::MIMETYPE.into(),
            &guess_mime_for_filename(filename),
            store,
        )?;
        resource.set_propval_string(urls::FILENAME.into(), filename, store)?;
        resource.set_propval_string(urls::DOWNLOAD_URL.into(), &download_url, store)?;
        commit_responses.push(resource.save(store)?);
        created_resources.push(resource);
    }

    let created_file_subjects = created_resources
        .iter()
        .map(|r| r.get_subject().to_string())
        .collect::<Vec<String>>();

    // Add the files as `attachments` to the parent
    let mut parent = store.get_resource(&query.parent)?;
    // parent.append_subjects(urls::ATTACHMENTS, created_file_subjects, false, store)?;
    for created in created_file_subjects {
        parent.push_propval(urls::ATTACHMENTS, created.into(), false)?;
    }
    commit_responses.push(parent.save(store)?);

    let mut builder = HttpResponse::Ok();

    Ok(builder.body(atomic_lib::serialize::resources_to_json_ad(
        &created_resources,
    )?))
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
