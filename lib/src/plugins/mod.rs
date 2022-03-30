// Plugins extend functionality of Atomic Server.
// It's currently only possible to return custom resources on getting a specific Class type.
// We use this for handling Invites, Files, `/search` and `/version`.
// Creating plugins currently requires creating a module in this repo, but we're working on WASM support.

pub mod bindings;
pub mod generated_runtime;
pub mod host;
