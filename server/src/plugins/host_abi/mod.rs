//! The host ABI (`atomic:host@0.1.0`, `atomic-host/wit/host.wit`): the one
//! typed interface between the server and a sandboxed app.
//!
//! See `planning/host-abi.md`. Pre-v1: this may break freely.
//!
//! An app is a wasip2 component of world `sandboxed-app`. Everything it can do
//! is an import the host wrote here:
//!
//! - [`store`]: `get`, `get-many`, `query`, `apply`, `subscribe`. Reads are
//!   checked against the caller and the Installation's agent
//!   ([`HostCore`]'s `Grant`), writes go through the existing planner and
//!   applier ([`crate::plugins::plan`], [`crate::plugins::apply`]) as the
//!   Installation's agent. Nothing runs as `Sudo`.
//! - [`net`]: `fetch` by manifest operation id, through [`HostCore::fetch`]
//!   (egress policy, pinned addresses, secret substitution).
//! - [`events`]: a pull stream with a cursor. In-memory in this slice.
//! - [`calls`]: `providers`, `describe` and `call` between apps in one drive.
//!   The callee runs with its own Installation's rights, never the caller's.
//!
//! The registry ([`HostAbiRegistry`]) holds the loaded apps; [`run`] holds the
//! component lifecycle, one fresh instance per invocation.
//!
//! Gaps in this slice, deliberately: handles passed to `calls.call` are
//! accepted and ignored (the callee gets exactly its own grant); `events` is a
//! per-process queue that nothing feeds yet but [`HostAbiRegistry::push_event`];
//! `search`, `undo` and the `ne` filter are `unsupported`; proposals are kept in
//! memory; `apply` is checked for rights before it writes but is not a single
//! store transaction.

mod calls;
mod convert;
mod events;
mod net;
mod registry;
mod run;
mod store;

#[cfg(test)]
mod wit_tests;

pub use registry::{HostAbiRegistry, LoadedApp, Proposal, MAX_CALL_DEPTH};
pub use run::{call_as, call_export, CallError};

pub(crate) mod bindings {
    wasmtime::component::bindgen!({
        path: "../atomic-host/wit",
        world: "sandboxed-app",
        imports: { default: async },
        exports: { default: async },
        additional_derives: [PartialEq],
    });
}

pub(crate) use bindings::atomic::host::types::Error as HostError;

/// Stable error codes of the ABI. `message` is for people, `code` is for code.
pub mod code {
    pub const NOT_FOUND: &str = "not-found";
    pub const FORBIDDEN: &str = "forbidden";
    pub const INVALID_ARGUMENT: &str = "invalid-argument";
    pub const UNSUPPORTED: &str = "unsupported";
    pub const DEPTH_EXCEEDED: &str = "depth-exceeded";
    pub const NEEDS_APPROVAL: &str = "needs-approval";
    pub const TRAP: &str = "trap";
    pub const INTERNAL: &str = "internal";
}

pub(crate) fn error(code: &str, message: impl Into<String>) -> HostError {
    HostError {
        code: code.to_string(),
        message: message.into(),
    }
}

/// A failure from the shared host, which reports `String`s, as an ABI error.
///
/// The code is read off the message because the shared code (`HostCore`,
/// `hierarchy`) flattens its errors to text; the match is deliberately small
/// and anything unknown is `internal`.
pub(crate) fn classify(message: String) -> HostError {
    let lower = message.to_lowercase();
    let code = if lower.contains("not found") || lower.contains("notfound") {
        code::NOT_FOUND
    } else if lower.contains("unauthorized")
        || lower.contains("no right")
        || lower.contains("rights")
        || lower.contains("permission")
        || lower.contains("not active")
        || lower.contains("revoked")
        || lower.contains("does not declare")
        || lower.contains("cannot reach")
        || lower.contains("proposal-only")
    {
        code::FORBIDDEN
    } else {
        code::INTERNAL
    };
    error(code, message)
}
