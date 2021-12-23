mod actor_messages;
mod appstate;
mod commit_monitor;
pub mod config;
mod content_types;
mod errors;
mod handlers;
mod helpers;
#[cfg(feature = "https")]
mod https;
mod jsonerrors;
mod process;
mod routes;
pub mod serve;
// #[cfg(feature = "search")]
mod search;
#[cfg(test)]
mod tests;
mod timer;
#[cfg(feature = "desktop")]
mod tray_icon;
