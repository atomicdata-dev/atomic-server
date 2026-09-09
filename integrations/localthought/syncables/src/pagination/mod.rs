//! The [OpenAPI Pagination Schemes Extension](https://github.com/pondersource/openapi-pagination-schemes-extension)
//! (`components.paginationSchemes`), applied to third-party documents via
//! [OpenAPI Overlays](https://spec.openapis.org/overlay/v1.0.0.html).
//!
//! **Pagination is orthogonal to the collection/item resource model.** In
//! real APIs, the paths that pair into a "resource" (batch-get-by-IDs
//! style, e.g. Giphy's `/gifs`, Spotify's `/albums`) are often *not* the
//! paginated ones — real pagination usually lives on separate search/list
//! endpoints (`/gifs/trending`, `/artists/{id}/albums`) that have no
//! sibling item path and are therefore invisible to
//! [`crate::resources::discover`]. So pagination support in both the mock
//! server and `paginate()` operates on *any* GET operation matched by a
//! scheme, not just discovered resources.

pub mod autodetect;
pub mod items;
pub mod request_builder;
pub mod response_parser;
pub mod types;
pub mod validate;
