/*!
Atomic-Server is mostly desgigned to run as a binary, but it can be embedded in other projects, too.
It is currently used as an embedded server in the Tauri distribution of Atomic Server.
See https://github.com/joepio/atomic-data-rust/tree/master/src-tauri

Minimal setup:

```
use atomic_server::{serve, config};
// You can pass atomic-server cli arguments here, or you could initialize the Opts struct manually.
let opts = config::Opts::parse_from(&["atomic-server", "--initialize"]);
let config = config::build_config(opts).expect("failed init config");
serve::serve(config).await;
```
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
mod process;
mod routes;
pub mod serve;
// #[cfg(feature = "search")]
mod search;
#[cfg(test)]
mod tests;
mod timer;
mod trace;
