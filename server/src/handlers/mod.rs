/*!
Handlers are Actix-powered endpoints that handle requests.
See `routes.rs` for the routing logic.
Most of the logic for routing and handling resides in [atomic_lib::Storelike::get_resource_extended] and its Plugins.
However, some features reside in atomic-server.
*/

pub mod blob;
pub mod commit;
pub mod download;
pub mod drive_usage;
pub mod export;
pub mod forget_peer;
pub mod get_resource;
pub mod history_attribution;
#[cfg(feature = "image")]
pub mod image;
pub mod plugin_ui;
pub mod post_resource;
pub mod search;
pub mod single_page_app;
pub mod upload;
#[cfg(feature = "vector-search")]
pub mod vector_search;
pub mod web_sockets;
pub mod ws_v2;
