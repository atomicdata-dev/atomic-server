/*!
Handlers are Actix-powered endpoints that handle requests.
Most of the logic for routing and handling resides in [atomic_lib::Storelike::get_resource_extended] and its Plugins.
However, some features reside in atomic-server.
*/

pub mod commit;
pub mod download;
pub mod resource;
pub mod search;
pub mod single_page_app;
pub mod tpf;
pub mod upload;
pub mod web_sockets;
