//! `atomic:host/net`: the outside world, only as the manifest declares it.
//!
//! A request names a manifest operation id. The host knows that operation's
//! method, endpoint and effect; the app supplies only a path under the
//! endpoint's origin, query pairs, headers and a body. Everything after that is
//! [`HostCore::fetch`]: the allowlist, the public-address check on the address
//! actually connected to, secret substitution scoped to the origin, and the
//! response cap.

use crate::plugins::host_core::FetchRequest;

use super::{
    bindings::atomic::host::net::{self, Header, Request, Response},
    classify, code, error,
    run::AbiState,
    HostError,
};

impl net::Host for AbiState {
    async fn fetch(&mut self, req: Request) -> Result<Response, HostError> {
        let manifest = &self.host.app.manifest;
        let operation = manifest
            .operations
            .iter()
            .find(|operation| operation.id == req.operation)
            .ok_or_else(|| {
                error(
                    code::FORBIDDEN,
                    format!(
                        "the manifest declares no operation '{}', so it does not do that",
                        req.operation
                    ),
                )
            })?;

        // Same rule as the JS runtime: an external write is something a person
        // approved as an intent, not something code decides mid-run.
        if operation.effect != "read" {
            return Err(error(
                code::NEEDS_APPROVAL,
                format!(
                    "'{}' has effect {}; only read operations can be fetched directly",
                    operation.id, operation.effect
                ),
            ));
        }

        let mut url = url::Url::parse(&operation.url)
            .map_err(|e| error(code::INTERNAL, format!("operation URL: {e}")))?;
        if !req.path.is_empty() {
            if !req.path.starts_with('/') {
                return Err(error(
                    code::INVALID_ARGUMENT,
                    "path must start with a slash",
                ));
            }
            url.set_path(&req.path);
        }
        if !req.query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(req.query.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        }

        let mut headers: Vec<(String, String)> = req
            .headers
            .into_iter()
            .map(|header| (header.name, header.value))
            .collect();
        if let Some(etag) = req.if_match {
            headers.push(("If-Match".into(), etag));
        }
        let body = match req.body {
            Some(bytes) => Some(String::from_utf8(bytes).map_err(|_| {
                error(
                    code::INVALID_ARGUMENT,
                    "request bodies must be UTF-8 text for now",
                )
            })?),
            None => None,
        };

        let response = self
            .host
            .core
            .fetch(
                FetchRequest {
                    operation: Some(operation.id.clone()),
                    method: operation.method.clone(),
                    url: url.to_string(),
                    headers,
                    body,
                },
                &operation.effect,
            )
            .await
            .map_err(classify)?;

        Ok(Response {
            status: response.status,
            headers: response
                .headers
                .into_iter()
                .map(|(name, value)| Header { name, value })
                .collect(),
            // `HostCore::fetch` reads the body as text, so a binary response
            // arrives lossy. Bytes all the way down is a follow-up.
            body: response.body.into_bytes(),
        })
    }
}
