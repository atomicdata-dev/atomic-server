/*!
Atomic-Server is mostly desgigned to run as a binary, but it can be embedded in other projects, too.
It is currently used as an embedded server in the Tauri distribution of Atomic Server.
See https://github.com/atomicdata-dev/atomic-server/tree/master/src-tauri
*/
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
mod routes;
pub mod serve;
// #[cfg(feature = "search")]
mod search;
#[cfg(test)]
mod tests;
mod trace;
