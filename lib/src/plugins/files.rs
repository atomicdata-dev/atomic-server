use crate::{endpoints::Endpoint, urls};

pub fn upload_endpoint() -> Endpoint {
    Endpoint {
        path: "/upload".to_string(),
        params: vec![urls::PARENT.into()],
        description: "In `atomic-server`, a `/upload` endpoint exists for uploading a file.\n\n- Decide where you want to add the file in the [hierarchy](hierarchy.md) of your server. You can add a file to any resource - your file will refer to this resource as its [`parent`](https://atomicdata.dev/properties/parent). Make sure you have `write` rights on this parent.\n- Use that parent to add a query parameter to the server's `/upload` endpoint, e.g. `/upload?parent=https%3A%2F%2Fatomicdata.dev%2Ffiles`.\n- Send an HTTP `POST` request to the server's `/upload` endpoint containing [`multi-part-form-data`](https://developer.mozilla.org/en-US/docs/Web/API/FormData/Using_FormData_Objects). You can upload multiple files in one request. Add [authentication](https://docs.atomicdata.dev/authentication.html) headers, and sign the HTTP request.\n- The server will check your authentication headers, your permissions, and will persist your uploaded file(s). It will now create File resources.\n- The server will reply with an array of created Atomic Data Files\n".to_string(),
        shortname: "upload".to_string(),
        handle: None,
        handle_post: None,
    }
}

pub fn download_endpoint() -> Endpoint {
    Endpoint {
        path: "/download".to_string(),
        params: vec![],
        description: "Downloads a file referenced by a file resource.\n Usualy you will interact with this endpoint by following the `download-url` property on a file resource.\n If the file is an image you can set a few query paremeters to make the server compress and scale the image for you.\n The following query parameters are available: \n- **f**: Format of the file, can be `webp` or `avif`. \n- **w**: The width the image should be scaled to. \n- **q**: Quality setting used during encoding. Must be a number between 0 - 100.".to_string(),
        shortname: "download".to_string(),
        handle: None,
        handle_post: None,
    }
}
