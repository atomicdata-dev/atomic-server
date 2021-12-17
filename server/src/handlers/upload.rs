use std::sync::Mutex;

use actix_multipart::Multipart;
use actix_web::{web, HttpResponse};
use async_std::prelude::*;
use atomic_lib::{
    datetime_helpers::now, hierarchy::check_write, urls, AtomicError, Resource, Storelike, Value,
};
use futures::{StreamExt, TryStreamExt};
use serde::Deserialize;

use crate::{appstate::AppState, errors::AtomicServerResult, helpers::get_client_agent};

#[derive(Deserialize)]
pub struct UploadQuery {
    parent: String,
}

/// Allows the user to upload files
pub async fn upload_handler(
    mut body: Multipart,
    data: web::Data<Mutex<AppState>>,
    query: web::Query<UploadQuery>,
    req: actix_web::HttpRequest,
) -> AtomicServerResult<HttpResponse> {
    let appstate = data.lock().unwrap();
    let store = &appstate.store;
    let parent = store.get_resource(&query.parent)?;
    let subject = format!("{}/{}", store.get_base_url(), req.head().uri);
    // if let Some(agent) = get_client_agent(req.headers(), &appstate, subject)? {
    //     check_write(store, &parent, &agent)?;
    // } else {
    //     return Err(AtomicError::unauthorized(
    //         "No authorization headers present. These are required when uploading files.".into(),
    //     )
    //     .into());
    // }

    let mut created_resources: Vec<Resource> = Vec::new();

    while let Ok(Some(mut field)) = body.try_next().await {
        let content_type = field
            .content_disposition()
            .ok_or("actix_web::error::ParseError::Incomplete")?;
        let filename = content_type.get_filename().ok_or("Filename is missing")?;

        let filesdir = format!("{}/uploads", appstate.config.config_dir.to_str().unwrap());
        async_std::fs::create_dir_all(&filesdir).await?;
        let file_id = format!("{}-{}", now(), sanitize_filename::sanitize(&filename));
        let file_path = format!("{}/{}", filesdir, file_id);
        let mut file = async_std::fs::File::create(file_path).await?;

        // Field in turn is stream of *Bytes* object
        while let Some(chunk) = field.next().await {
            let data = chunk.unwrap();
            // TODO: Maybe update a SHA256 hash here
            file.write_all(&data).await?;
        }

        let byte_count: i64 = file
            .metadata()
            .await?
            .len()
            .try_into()
            .map_err(|_e| "Too large")?;

        // TODO: Generate mimetype
        // let mimetype = "application/text";

        // TODO: generate hash
        let checksum = file_id;

        let mut resource = atomic_lib::Resource::new_instance(urls::FILE, store)?;
        resource.set_propval_string(urls::PARENT.into(), &query.parent, store)?;
        resource.set_propval_string(urls::CHECKSUM.into(), &checksum, store)?;
        resource.set_propval(urls::FILESIZE.into(), Value::Integer(byte_count), store)?;
        // resource.set_propval_string(urls::MIMETYPE.into(), "appication/", store)?;
        resource.set_propval_string(urls::FILENAME.into(), filename, store)?;
        resource.save(store)?;
        created_resources.push(resource);
    }

    let mut builder = HttpResponse::Ok();

    Ok(builder.body(atomic_lib::serialize::resources_to_json_ad(
        &created_resources,
    )?))
}
