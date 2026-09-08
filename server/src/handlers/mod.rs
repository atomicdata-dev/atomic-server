/*!
Handlers are Actix-powered endpoints that handle requests.
See `routes.rs` for the routing logic.
Most of the logic for routing and handling resides in [atomic_lib::Storelike::get_resource_extended] and its Plugins.
However, some features reside in atomic-server.
*/

pub mod app_agent;
#[cfg(all(test, feature = "wasm-plugins"))]
mod app_endpoints_test;
pub mod app_write;
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
#[cfg(feature = "wasm-plugins")]
pub mod plugin_connection;
pub mod plugin_external;
pub mod plugin_release;
pub mod plugin_run;
pub mod plugin_schedule;
pub mod plugin_secret;
pub mod plugin_trigger;
pub mod plugin_ui;
pub mod post_resource;
pub mod search;
pub mod single_page_app;
pub mod upload;
#[cfg(feature = "vector-search")]
pub mod vector_search;
pub mod web_sockets;
pub mod ws_v2;

#[cfg(feature = "wasm-plugins")]
pub mod plugin_sync;

#[cfg(feature = "wasm-plugins")]
pub mod integration_action;

pub mod integration_oauth;
