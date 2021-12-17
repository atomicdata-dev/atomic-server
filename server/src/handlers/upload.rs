use std::sync::Mutex;

use actix_multipart::Multipart;
use actix_web::{web, Error, HttpResponse};
use async_std::prelude::*;
use futures::{StreamExt, TryStreamExt};

use crate::appstate::AppState;

/// Allows the user to upload files
// reference from https://github.com/actix/examples/tree/master/multipart-async-std
pub async fn upload_handler(
    mut body: Multipart,
    data: web::Data<Mutex<AppState>>,
) -> Result<HttpResponse, Error> {
    // let appstate = data.lock().await;
    let appstate = data.lock().unwrap();

    // let store = &appstate.store;

    // iterate over multipart stream
    while let Ok(Some(mut field)) = body.try_next().await {
        let content_type = field
            .content_disposition()
            .ok_or(actix_web::error::ParseError::Incomplete)?;
        let filename = content_type
            .get_filename()
            .ok_or(actix_web::error::ParseError::Incomplete)?;
        // TODO: Guarantee unique filename
        // TODO: Use custom folder
        let filesdir = format!("{}/uploads", appstate.config.config_dir.to_str().unwrap());
        async_std::fs::create_dir_all(&filesdir).await?;
        let filepath = format!("{}/{}", filesdir, sanitize_filename::sanitize(&filename));
        let mut file = async_std::fs::File::create(filepath).await?;

        // TODO: Create Atomic Data Resource for file
        // TODO: Authorization checks

        // Field in turn is stream of *Bytes* object
        while let Some(chunk) = field.next().await {
            let data = chunk.unwrap();
            file.write_all(&data).await?;
        }
    }
    Ok(HttpResponse::Ok().into())
}
