// Plugins extend functionality of Atomic Server.
// It's currenlty only possible to return custom resources on getting a specific Class type.
// We use this for handling Invites, Files, `/search` and `/version`.
// Creating plugins currently requires creating a module in this repo, but we're working on WASM support.

pub mod invite;

// Endpoints:
// When adding an endpoint, add it to the list of endpoints in lib/src/endpoints.rs
pub mod files;
pub mod path;
pub mod plugin;
pub mod search;
pub mod versioning;
pub mod wasm_demo;
