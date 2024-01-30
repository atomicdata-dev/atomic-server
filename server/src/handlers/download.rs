use std::time::Duration;

use actix_files::NamedFile;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use atomic_lib::{urls, Storelike};

use crate::{
    appstate::AppState,
    errors::AtomicServerResult,
    files::{self, FileStore},
    helpers::get_client_agent,
};

/// Downloads the File of the Resource that matches the same URL minus the `/download` path.
#[tracing::instrument(skip(appstate, req))]
pub async fn handle_download(
    path: Option<web::Path<String>>,
    appstate: web::Data<AppState>,
    req: actix_web::HttpRequest,
) -> AtomicServerResult<HttpResponse> {
    let headers = req.headers();
    let server_url = &appstate.config.server_url;
    let store = &appstate.store;

    // We replace `/download` with `/` to get the subject of the Resource.
    let subject = if let Some(pth) = path {
        let subject = format!("{}/{}", server_url, pth);
        subject
    } else {
        // There is no end string, so It's the root of the URL, the base URL!
        return Err("Put `/download` in front of an File URL to download it.".into());
    };

    let for_agent = get_client_agent(headers, &appstate, subject.clone())?;
    tracing::info!("handle_download: {}", subject);
    let file_store = FileStore::get_subject_file_store(&appstate, &subject);
    let encoded = subject.replace(file_store.prefix(), &file_store.encoded());
    let resource = store.get_resource_extended(&encoded, false, &for_agent)?;
    let file_id = resource
        .get(urls::INTERNAL_ID)
        .map_err(|e| format!("Internal ID of file could not be resolved. {}", e))?
        .to_string();

    if let FileStore::S3(_) = file_store {
        signed_url_redirect_handler(file_id.as_str(), &req, &appstate).await
    } else {
        download_file_handler_partial(file_id.as_str(), &req, &appstate)
    }
}

pub fn download_file_handler_partial(
    file_id: &str,
    req: &HttpRequest,
    appstate: &AppState,
) -> AtomicServerResult<HttpResponse> {
    let file_path = appstate.fs_file_store.get_fs_file_path(file_id)?;
    let file = NamedFile::open(file_path)?;
    Ok(file.into_response(req))
}

async fn signed_url_redirect_handler(
    file_id: &str,
    req: &HttpRequest,
    appstate: &AppState,
) -> AtomicServerResult<HttpResponse> {
    let signed_url =
        files::get_s3_signed_url(&appstate.file_store, Duration::from_secs(3600), file_id).await?;
    Ok(web::Redirect::to(signed_url)
        .respond_to(req)
        .map_into_boxed_body())
}
