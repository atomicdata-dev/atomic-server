use actix_files::NamedFile;
use actix_web::{web, HttpRequest, HttpResponse};
use atomic_lib::{urls, Resource, Storelike};

use crate::{appstate::AppState, errors::AtomicServerResult, helpers::get_client_agent};

/// Downloads the File of the Resource that matches the same URL minus the `/download` path.
#[tracing::instrument(skip(appstate, req))]
pub async fn handle_download(
    path: Option<web::Path<String>>,
    appstate: web::Data<AppState>,
    req: actix_web::HttpRequest,
) -> AtomicServerResult<HttpResponse> {
    let headers = req.headers();
    let store = &appstate.store;

    // We replace `/download` with `/` to get the subject of the Resource.
    let subject = if let Some(pth) = path {
        appstate
            .store
            .get_server_url()
            .clone()
            .set_path(pth.as_str())
            .to_string()
    } else {
        // There is no end string, so It's the root of the URL, the base URL!
        return Err("Put `/download` in front of an File URL to download it.".into());
    };

    let for_agent = get_client_agent(headers, &appstate, subject.clone())?;
    tracing::info!("handle_download: {}", subject);
    let resource = store.get_resource_extended(&subject, false, &for_agent)?;
    download_file_handler_partial(&resource, &req, &appstate)
}

pub fn download_file_handler_partial(
    resource: &Resource,
    req: &HttpRequest,
    appstate: &AppState,
) -> AtomicServerResult<HttpResponse> {
    let file_name = resource
        .get(urls::INTERNAL_ID)
        .map_err(|e| format!("Internal ID of file could not be resolved. {}", e))?;
    let mut file_path = appstate.config.uploads_path.clone();
    file_path.push(file_name.to_string());
    let file = NamedFile::open(file_path)?;
    Ok(file.into_response(req))
}
