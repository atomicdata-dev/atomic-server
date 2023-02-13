/*!
Handlers are Actix-powered endpoints that handle requests.
See `routes.rs` for the routing logic.
Most of the logic for routing and handling resides in [atomic_lib::Storelike::get_resource_extended] and its Plugins.
However, some features reside in atomic-server.
*/

pub mod commit;
pub mod download;
pub mod get_resource;
pub mod post_resource;
pub mod search;
pub mod single_page_app;
pub mod upload;
pub mod web_sockets;
