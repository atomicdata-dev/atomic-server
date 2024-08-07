{{#title Uploading, downloading and describing files with Atomic Data}}
# Uploading, downloading and describing files with Atomic Data

The Atomic Data model (Atomic Schema) is great for describing structured data, but for many types of existing data, we already have a different way to represent them: files.
In Atomic Data, files have two URLs.
One _describes_ the file and its metadata, and the other is a URL that downloads the file.
This allows us to present a better view when a user wants to take a look at some file, and learn about its context before downloading it.

## The File class

_url: [https://atomicdata.dev/classes/File](https://atomicdata.dev/classes/File)_

Files always have a downloadURL.
They often also have a filename, a filesize, a checksum, a mimetype, and an internal ID (more on that later).
They also often have a [`parent`](https://atomicdata.dev/properties/parent), which can be used to set permissions / rights.
If the file is an image they will also get an `imageWidth` and `imageHeight` property.

## Uploading a file

In `atomic-server`, a `/upload` endpoint exists for uploading a file.

- Decide where you want to add the file in the [hierarchy](hierarchy.md) of your server. You can add a file to any resource - your file will refer to this resource as its [`parent`](https://atomicdata.dev/properties/parent). Make sure you have `write` rights on this parent.
- Use that parent to add a query parameter to the server's `/upload` endpoint, e.g. `/upload?parent=https%3A%2F%2Fatomicdata.dev%2Ffiles`.
- Send an HTTP `POST` request to the server's `/upload` endpoint containing [`multi-part-form-data`](https://developer.mozilla.org/en-US/docs/Web/API/FormData/Using_FormData_Objects). You can upload multiple files in one request. Add [authentication](authentication.md) headers, and sign the HTTP request with the
- The server will check your authentication headers, your permissions, and will persist your uploaded file(s). It will now create File resources.
- The server will reply with an array of created Atomic Data Files

## Downloading a file

Simply send an HTTP GET request to the File's [`download-url`](https://atomicdata.dev/properties/downloadURL) (make sure to authenticate this request).

### Image compression

AtomicServer can automatically generate compressed versions of images in modern image formats (WebP, AVIF).
To do this add one or more of the following query parameters to the download URL:

| Query parameter | Description |
| --- | --- |
| f | The format of the image. Can be `webp` or `avif`. |
| q | The quality used to encode the image. Can be a number between 0 and 100. (Only works when `f` is set to `webp` or `avif`). Default is 75|
| w | The width of the image. Height will be scaled based on the width to keep the right aspect-ratio |

Example: `https://atomicdata.dev/download/files/1668879942069-funny-meme.jpg?f=avif&q=60&w=500`

## Discussion

- [Discussion on specification](https://github.com/ontola/atomic-data-docs/issues/57)
- [Discussion on Rust server implementation](https://github.com/atomicdata-dev/atomic-server/issues/72)
- [Discussion on Typescript client implementation](https://github.com/atomicdata-dev/atomic-data-browser/issues/121)
