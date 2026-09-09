//! Credentials presented to the API being reflected, and the base URL they
//! are presented against.
//!
//! Ported from `Credentials` in the syncables-rs API contract mirrored at
//! [`localthought/reflector-rs`'s `src/syncables.rs`](https://github.com/localthought/reflector-rs/blob/main/src/syncables.rs),
//! and from `StaticTokenManager` in
//! [`localthought/reflector`](https://github.com/localthought/reflector)'s
//! `src/oauth/static-token.ts`, which is what actually attaches the header
//! and retargets a request at the real API base in the TypeScript
//! original.

use crate::openapi::types::OpenApiDocument;

/// Credentials presented to the API being reflected.
///
/// Only a static bearer token is modelled so far: that is what the GitHub
/// auth overlay's `http`/`bearer` security scheme asks for. An interactive
/// OAuth profile — derived from the document the way the TypeScript
/// Reflector derives Google Calendar's — is tracked separately (see
/// [issue #5](https://github.com/localthought/syncables-rs/issues/5)).
#[derive(Clone, PartialEq, Eq)]
pub enum Credentials {
    /// Sent as `Authorization: Bearer <token>`.
    Bearer(String),
    /// No credential — only useful against a public, unauthenticated API.
    Anonymous,
}

impl std::fmt::Debug for Credentials {
    /// Never renders the secret, so `{:?}` on a config that holds one is
    /// safe to log. A host logging its resolved configuration at startup is
    /// exactly the scenario this guards against.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Credentials::Bearer(_) => f.write_str("Bearer(<redacted>)"),
            Credentials::Anonymous => f.write_str("Anonymous"),
        }
    }
}

impl Credentials {
    /// The `Authorization` header value to send with every request, if any.
    ///
    /// [`Credentials::Anonymous`] sends no `Authorization` header at all —
    /// distinct in principle from an empty bearer token, which would still
    /// be presented.
    #[must_use]
    pub fn authorization_header(&self) -> Option<String> {
        match self {
            Credentials::Bearer(token) => Some(format!("Bearer {token}")),
            Credentials::Anonymous => None,
        }
    }
}

/// The API's base URL, read from the document's `servers` — never from
/// separate configuration, so a document can't be pointed at the wrong host
/// by a configuration mismatch.
///
/// Returns the first declared server, matching the TypeScript original's
/// `StaticTokenManager`/`TokenManager`, which likewise target whatever
/// `servers[0]` names. `None` if the document declares no servers at all.
#[must_use]
pub fn base_url(document: &OpenApiDocument) -> Option<&str> {
    document
        .servers
        .as_ref()?
        .first()
        .map(|server| server.url.as_str())
}
