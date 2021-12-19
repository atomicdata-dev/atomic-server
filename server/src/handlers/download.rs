use std::sync::Mutex;

use actix_files::NamedFile;
use actix_web::{web, HttpRequest, HttpResponse};
use atomic_lib::{urls, Resource, Storelike};

use crate::{appstate::AppState, errors::AtomicServerResult, helpers::get_client_agent};

/// Downloads the File of the Resource that matches the same URL minus the `/download` path.
pub async fn handle_download(
    path: Option<web::Path<String>>,
    data: web::Data<Mutex<AppState>>,
    req: actix_web::HttpRequest,
) -> AtomicServerResult<HttpResponse> {
    let appstate = data.lock().unwrap();
    let headers = req.headers();
    let base_url = &appstate.config.local_base_url;
    let store = &appstate.store;

    // We replace `/download` with `/` to get the subject of the Resource.
    let subject = if let Some(pth) = path {
        let subject = format!("{}/{}", base_url, pth);
        subject
    } else {
        // There is no end string, so It's the root of the URL, the base URL!
        return Err("Put `/download` in front of an File URL to download it.".into());
    };

    let for_agent = get_client_agent(headers, &appstate, subject.clone())?;
    log::info!("handle_download: {}", subject);
    let resource = store.get_resource_extended(&subject, false, for_agent.as_deref())?;
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
    Ok(file.into_response(req)?)
}
