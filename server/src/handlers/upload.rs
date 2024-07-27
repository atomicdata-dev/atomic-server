use std::{ffi::OsStr, path::Path};

use actix_multipart::Multipart;
use actix_web::{web, HttpResponse};
use atomic_lib::{
    commit::CommitResponse, hierarchy::check_write, urls, utils::now, Resource, Storelike, Value,
};

use futures::TryStreamExt;
use serde::Deserialize;

use crate::{appstate::AppState, errors::AtomicServerResult, helpers::get_client_agent};

#[derive(Deserialize, Debug)]
pub struct UploadQuery {
    parent: String,
}

/// Allows the user to upload files to the `/upload` endpoint.
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
) -> AtomicServerResult<HttpResponse> {
    let store = &appstate.store;
    let parent = store.get_resource(&query.parent)?;
    let subject = format!(
        "{}{}",
        store.get_server_url(),
        req.head()
            .uri
            .path_and_query()
            .ok_or("Path must be given")?
    );
    let agent = get_client_agent(req.headers(), &appstate, subject)?;
    check_write(store, &parent, &agent)?;

    let mut created_resources: Vec<Resource> = Vec::new();
    let mut commit_responses: Vec<CommitResponse> = Vec::new();

    while let Ok(Some(field)) = body.try_next().await {
        let content_type = field.content_disposition().clone();
        let filename = content_type.get_filename().ok_or("Filename is missing")?;

        let file_store = &appstate.file_store;
        let file_id = format!(
            "{}{}-{}",
            file_store.prefix(),
            now(),
            sanitize_filename::sanitize(filename)
                // Spacebars lead to very annoying bugs in browsers
                .replace(' ', "-")
        );

        let byte_count = file_store.upload_file(&file_id, field).await?;

        let subject_path = format!("files/{}", urlencoding::encode(&file_id));
        let new_subject = format!("{}/{}", store.get_server_url(), subject_path);
        let download_url = format!("{}/download/{}", store.get_server_url(), subject_path);

        let mut resource = atomic_lib::Resource::new_instance(urls::FILE, store)?;
        resource
            .set_subject(new_subject)
            .set_string(urls::PARENT.into(), &query.parent, store)?
            .set_string(urls::INTERNAL_ID.into(), &file_id, store)?
            .set(urls::FILESIZE.into(), Value::Integer(byte_count), store)?
            .set_string(
                urls::MIMETYPE.into(),
                &guess_mime_for_filename(filename),
                store,
            )?
            .set_string(urls::FILENAME.into(), filename, store)?
            .set_string(urls::DOWNLOAD_URL.into(), &download_url, store)?;
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
        parent.push(urls::ATTACHMENTS, created.into(), false)?;
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
