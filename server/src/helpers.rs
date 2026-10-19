//! Functions useful in the server

use actix_web::cookie::Cookie;
use actix_web::http::header::{HeaderMap, HeaderValue};
use actix_web::http::Uri;
use atomic_lib::agents::ForAgent;
use atomic_lib::authentication::AuthValues;
use atomic_lib::AtomicError;
use percent_encoding::percent_decode_str;
use std::str::FromStr;

use crate::errors::{AppErrorType, AtomicServerError};
use crate::{appstate::AppState, content_types::ContentType, errors::AtomicServerResult};

/// The method and the body bytes a handler acts on, which a version 2
/// request signature (`x-atomic-signature-version: 2`) must cover.
#[derive(Clone, Copy)]
pub struct SignedRequest<'a> {
    pub method: &'a str,
    pub body: &'a [u8],
}

/// Which request signature version the headers ask for. Absent is 1.
/// Anything but `1` or `2` is refused rather than guessed at.
fn requested_signature_version(map: &HeaderMap) -> AtomicServerResult<u8> {
    match map.get(atomic_lib::authentication::SIGNATURE_VERSION_HEADER) {
        None => Ok(1),
        Some(v) => match v.to_str().map(str::trim) {
            Ok("1") => Ok(1),
            Ok(atomic_lib::authentication::SIGNATURE_VERSION_2) => Ok(2),
            _ => Err(AtomicError::unauthorized(
                "Unsupported x-atomic-signature-version; this server accepts 1 and 2".into(),
            )
            .into()),
        },
    }
}

/// Returns the authentication headers from the request.
///
/// For a caller that cannot say what method and body it acts on (a WebSocket
/// upgrade, most handlers today), so a version 2 signature is refused here
/// rather than checked as version 1. See [get_auth_headers_for_request].
#[tracing::instrument(skip_all)]
pub fn get_auth_headers(
    map: &HeaderMap,
    requested_subject: &str,
) -> AtomicServerResult<Option<AuthValues>> {
    get_auth_headers_for_request(map, requested_subject, None)
}

/// Returns the authentication headers from the request, checking a version 2
/// signature against `request` when the headers ask for one.
///
/// Version 2 never falls back to version 1: a v2 request that this caller
/// cannot bind (`request` is `None`), or that comes as a bearer token instead
/// of headers, is refused.
#[tracing::instrument(skip_all)]
pub fn get_auth_headers_for_request(
    map: &HeaderMap,
    requested_subject: &str,
    request: Option<SignedRequest>,
) -> AtomicServerResult<Option<AuthValues>> {
    let binding = match requested_signature_version(map)? {
        1 => None,
        _ => {
            let Some(request) = request else {
                return Err(AtomicError::unauthorized(
                    "This endpoint does not check version 2 request signatures yet. Sign it with version 1 (omit x-atomic-signature-version).".into(),
                )
                .into());
            };
            if map.get("authorization").is_some() {
                return Err(AtomicError::unauthorized(
                    "A version 2 request signature goes in the x-atomic-* headers, not in Authorization".into(),
                )
                .into());
            }
            Some(atomic_lib::authentication::RequestBinding::new(
                request.method,
                request.body,
            ))
        }
    };

    if binding.is_none() {
        if let Some(bearer) = map.get("authorization") {
            let bearer = bearer
                .to_str()
                .map_err(|_e| "Only string headers allowed in authorization header")?
                .trim_start_matches("Bearer ");
            let auth_vals = get_auth_from_base64(bearer, requested_subject)?;
            return Ok(Some(auth_vals));
        }
    }

    let public_key = map.get("x-atomic-public-key");
    let signature = map.get("x-atomic-signature");
    let timestamp = map.get("x-atomic-timestamp");
    let agent = map.get("x-atomic-agent");
    match (public_key, signature, timestamp, agent) {
        (Some(pk), Some(sig), Some(ts), Some(a)) => Ok(Some(AuthValues {
            public_key: pk
                .to_str()
                .map_err(|_e| "Only string headers allowed")?
                .to_string(),
            signature: sig
                .to_str()
                .map_err(|_e| "Only string headers allowed")?
                .to_string(),
            agent_subject: a
                .to_str()
                .map_err(|_e| "Only string headers allowed")?
                .to_string(),
            timestamp: ts
                .to_str()
                .map_err(|_e| "Only string headers allowed")?
                .parse::<i64>()
                .map_err(|_e| "Timestamp must be a number (milliseconds since unix epoch)")?,
            requested_subject: requested_subject.to_string(),
            request: binding,
        })),
        // Asking for v2 and sending no proof is not "anonymous": a cookie
        // must not stand in for the signature that was promised.
        (None, None, None, None) if binding.is_some() => Err(
            "x-atomic-signature-version: 2 without the x-atomic-* authentication headers".into(),
        ),
        (None, None, None, None) => Ok(None),
        _missing => Err("Missing authentication headers. You need `x-atomic-public-key`, `x-atomic-signature`, `x-atomic-agent` and `x-atomic-timestamp` for authentication checks.".into()),
    }
}

/// The `scheme://authority` part of `url`, or `None` when it has no scheme or
/// authority. The input is attacker-influenced (it is built from the request
/// `Host` / forwarded headers and the path), so this must never panic.
fn origin(url: &str) -> Option<String> {
    if url.starts_with("internal:/") {
        return Some(url.to_string());
    }
    let parsed = Uri::from_str(url).ok()?;
    Some(format!(
        "{}://{}",
        parsed.scheme_str()?,
        parsed.authority()?
    ))
}

pub fn get_auth_from_cookie(
    headers: &HeaderMap,
    requested_subject: &str,
) -> AtomicServerResult<Option<AuthValues>> {
    let encoded_session_cookies = match headers.get("Cookie") {
        Some(cookies) => session_cookies_from_header(cookies)?,
        None => return Ok(None),
    };

    if encoded_session_cookies.is_empty() {
        return Ok(None);
    }
    // if there are multiple session cookies, we can try multiple
    let check_multiple = encoded_session_cookies.len() > 1;

    let mut err: AtomicServerError =
        AtomicError::unauthorized("No valid session cookies found. ".into()).into();

    for enc in encoded_session_cookies {
        match get_auth_from_base64(&enc, requested_subject) {
            Ok(auth_vals) => return Ok(Some(auth_vals)),
            Err(e) => {
                if e.message.contains(WRONG_SUBJECT_ERR) && check_multiple {
                    // if the subject is wrong, we can try the next one
                    err = e;
                    continue;
                } else {
                    return Err(e);
                }
            }
        }
    }

    Err(err)
}

static WRONG_SUBJECT_ERR: &str = "Wrong requested subject in auth token";

fn get_auth_from_base64(base64: &str, requested_subject: &str) -> AtomicServerResult<AuthValues> {
    use base64::Engine;

    let session = base64::engine::general_purpose::STANDARD
        .decode(base64)
        .map_err(|_| {
            AtomicError::unauthorized(
                "Malformed authentication resource - unable to decode base64".to_string(),
            )
        })?;

    let session_str = std::str::from_utf8(&session).map_err(|_| AtomicServerError {
        message: "Malformed authentication resource - unable to parse from utf_8".to_string(),
        error_type: AppErrorType::Unauthorized,
        error_resource: None,
    })?;
    let auth_values: AuthValues =
        serde_json::from_str(session_str).map_err(|e| AtomicServerError {
            message: format!(
                "Malformed authentication resource when parsing AuthValues JSON: {}",
                e
            ),
            error_type: AppErrorType::Unauthorized,
            error_resource: None,
        })?;
    let subject_invalid = auth_values.requested_subject.ne(requested_subject)
        && origin(requested_subject)
            .map(|o| auth_values.requested_subject.ne(&o))
            .unwrap_or(true);
    if subject_invalid {
        // if the subject is invalid, there are two things that could be going on.
        // 1. The requested resource is wrong
        // 2. The user is trying to access a resource from a different origin

        let err = AtomicError::unauthorized(format!(
            "{}, expected {} was {}",
            WRONG_SUBJECT_ERR, requested_subject, auth_values.requested_subject
        ))
        .into();
        return Err(err);
    }
    Ok(auth_values)
}

/// Authentication from the `x-atomic-*` headers, or else from the session
/// cookie. A version 2 signature is checked against `request`.
pub fn get_auth_for_request(
    map: &HeaderMap,
    requested_subject: &str,
    request: Option<SignedRequest>,
) -> AtomicServerResult<Option<AuthValues>> {
    let from_header = get_auth_headers_for_request(map, requested_subject, request)?;

    match from_header {
        Some(v) => Ok(Some(v)),
        None => get_auth_from_cookie(map, requested_subject),
    }
}

/// Checks for authentication headers and returns Some agent's subject if everything is well.
/// Skips these checks in public_mode and returns Ok(None).
///
/// A version 2 request signature is refused here, since this caller does not
/// say which method and body it acts on; see [get_client_agent_for_request].
#[tracing::instrument(skip(appstate))]
pub async fn get_client_agent(
    headers: &HeaderMap,
    appstate: &AppState,
    requested_subject: &str,
) -> AtomicServerResult<ForAgent> {
    get_client_agent_checked(headers, None, appstate, requested_subject).await
}

/// The caller must be allowed to write the plugin: that is what makes it their
/// schedule, trigger or secret to set, and what lets them spend the plugin's
/// secrets unattended.
///
/// The client signs the request URL (and, with a version 2 signature, the
/// method and `body`), so that is what the signature is checked against.
/// Passing the plugin subject here made every signed request fail
/// verification; the rights check is what decides whether this agent may touch
/// this plugin. Pass `&[]` for a request without a body.
pub(crate) async fn authorize_plugin_write(
    appstate: &AppState,
    req: &actix_web::HttpRequest,
    context: &crate::context::RequestContext,
    body: &[u8],
    plugin: &str,
) -> AtomicServerResult<ForAgent> {
    use atomic_lib::Storelike;
    let store = &appstate.store;
    let resource = store.get_resource(&plugin.into()).await?;

    let agent = authenticate(req, appstate, context, body).await?;
    atomic_lib::hierarchy::check_write(store, &resource, &agent).await?;

    Ok(agent)
}

/// The URL a client signs for `req`: its path and query, resolved against
/// `origin`.
pub(crate) fn signed_subject(
    req: &actix_web::HttpRequest,
    origin: &str,
) -> AtomicServerResult<String> {
    let path_and_query = req
        .head()
        .uri
        .path_and_query()
        .ok_or("Path must be given")?
        .to_string();
    Ok(atomic_lib::Subject::from_raw(&path_and_query, None).resolve(origin))
}

/// Who signed `req`, checked against the request URL, its method and `body`
/// (a version 2 signature covers the latter two; version 1 only the URL and
/// is still accepted). Pass `&[]` for a request without a body. Every handler
/// that authenticates a request should come through here.
pub(crate) async fn authenticate(
    req: &actix_web::HttpRequest,
    appstate: &AppState,
    context: &crate::context::RequestContext,
    body: &[u8],
) -> AtomicServerResult<ForAgent> {
    let subject = context.signed_subject(req)?;
    get_client_agent_for_request(req, body, appstate, &subject).await
}

/// Parse a JSON request body that was read as raw bytes, so the same bytes can
/// be handed to [authenticate]. A parse error is a 400.
pub(crate) fn parse_json<T: serde::de::DeserializeOwned>(body: &[u8]) -> AtomicServerResult<T> {
    serde_json::from_slice(body)
        .map_err(|e| AtomicServerError::bad_request(format!("Invalid JSON body: {e}")))
}

/// The body limit for routes that read JSON as `web::Bytes`; it is what
/// actix's `JsonConfig` allowed before (2 MiB).
pub(crate) const JSON_BODY_LIMIT: usize = 2_097_152;

/// [get_client_agent] for a handler that knows the body it acts on, so it
/// also accepts a version 2 request signature (`x-atomic-signature-version:
/// 2`, ontola/atomic-plugins#54), which covers the method and that body.
/// Pass `&[]` for a handler that reads no body. Version 1 is still accepted.
#[tracing::instrument(skip(appstate, req, body))]
pub async fn get_client_agent_for_request(
    req: &actix_web::HttpRequest,
    body: &[u8],
    appstate: &AppState,
    requested_subject: &str,
) -> AtomicServerResult<ForAgent> {
    let request = SignedRequest {
        method: req.method().as_str(),
        body,
    };
    get_client_agent_checked(req.headers(), Some(request), appstate, requested_subject).await
}

async fn get_client_agent_checked(
    headers: &HeaderMap,
    request: Option<SignedRequest<'_>>,
    appstate: &AppState,
    requested_subject: &str,
) -> AtomicServerResult<ForAgent> {
    if appstate.config.opts.public_mode {
        return Ok(ForAgent::Public);
    }
    // Authentication check. If the user has no headers, continue with the Public Agent.
    // Whatever goes wrong from here — headers that do not parse, a signature
    // that does not verify, an unknown agent — the caller is not who they
    // claim to be, which is a 401, not a 500. Converting the error to a
    // string here used to lose the lib's `Unauthorized` type, so every
    // failed sign-in reported itself as a server crash (security audit D).
    let auth_header_values =
        get_auth_for_request(headers, requested_subject, request).map_err(unauthorized)?;
    // `_or_public`, not `_and_check`: nothing here asked to be authenticated.
    // A proof that has aged out makes this caller nobody, and the rights check
    // below decides whether that matters for what was requested.
    let for_agent = atomic_lib::authentication::get_agent_from_auth_values_or_public(
        auth_header_values,
        &appstate.store,
    )
    .await
    .map_err(|e| unauthorized(format!("Authentication failed: {}", e).into()))?;
    Ok(for_agent)
}

/// `error`, answered as 401 whatever it was typed as.
fn unauthorized(error: AtomicServerError) -> AtomicServerError {
    AtomicServerError {
        error_type: AppErrorType::Unauthorized,
        ..error
    }
}

/// Rate-limit key for a request without a signed agent: the socket peer
/// address. Deliberately not `X-Forwarded-For`: a direct client could spoof
/// that header to dodge the limit. Behind a reverse proxy every anonymous
/// write then shares one bucket, which fails closed rather than open.
pub fn peer_ip(req: &actix_web::HttpRequest) -> String {
    req.peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Spend one write token for this request, keyed by the signed agent when
/// there is one and by the peer address otherwise. `Sudo` is the node's own
/// process and is never limited. Call it after authentication and before any
/// work, so a flood costs the node nothing beyond the check.
pub fn enforce_write_rate_limit(
    appstate: &AppState,
    req: &actix_web::HttpRequest,
    for_agent: &ForAgent,
) -> AtomicServerResult<()> {
    let result = match for_agent {
        ForAgent::Sudo => return Ok(()),
        ForAgent::AgentSubject(subject) => appstate
            .write_rate_limiter
            .check(&subject.to_string(), false),
        ForAgent::Public => appstate.write_rate_limiter.check(&peer_ip(req), true),
    };
    result.map_err(|limited| AtomicServerError {
        message: limited.to_string(),
        error_type: AppErrorType::TooManyRequests,
        error_resource: None,
    })
}

/// Finds the extension
pub fn try_extension(path: &str) -> Option<(ContentType, &str)> {
    let items: Vec<&str> = path.split('.').collect();
    if items.len() == 2 {
        let path = items[0];
        let content_type = match items[1] {
            "json" => ContentType::Json,
            "jsonld" => ContentType::JsonLd,
            "jsonad" => ContentType::JsonAd,
            "html" => ContentType::Html,
            "ttl" => ContentType::Turtle,
            _ => return None,
        };
        return Some((content_type, path));
    }
    None
}

fn session_cookies_from_header(header: &HeaderValue) -> AtomicServerResult<Vec<String>> {
    let cookies: Vec<&str> = header
        .to_str()
        .map_err(|_| "Can't convert header value to string")?
        .split(';')
        .collect();

    let mut found = Vec::new();

    for encoded_cookie in cookies {
        let cookie = Cookie::parse(encoded_cookie).map_err(|_| "Can't parse cookie")?;
        if cookie.name() == "atomic_session" {
            let decoded = percent_decode_str(cookie.value())
                .decode_utf8()
                .map_err(|_| "Can't decode cookie string")?;
            found.push(decoded.into());
        }
    }

    Ok(found)
}

#[cfg(test)]
mod test {
    use actix_web::http::header::{HeaderMap, HeaderValue};
    use atomic_lib::Storelike;

    use super::*;
    use crate::tests::init_test_appstate;

    /// A 32-byte ed25519 seed. Any 32 bytes are a valid one.
    const PRIVATE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// A `Cookie` header holding the auth proof a browser would have stored at
    /// `timestamp`, exactly as `setCookieAuthentication` writes it.
    fn cookie_header(server_url: &str, timestamp: i64) -> HeaderMap {
        use base64::Engine;
        let pair = atomic_lib::agents::generate_public_key(PRIVATE_KEY);
        let signature = atomic_lib::agents::sign_message(
            format!("{} {}", server_url, timestamp).as_bytes(),
            &pair.private,
        )
        .unwrap();
        let proof = serde_json::json!({
            "https://atomicdata.dev/properties/auth/agent":
                format!("did:ad:agent:{}", pair.public),
            "https://atomicdata.dev/properties/auth/requestedSubject": server_url,
            "https://atomicdata.dev/properties/auth/publicKey": pair.public,
            "https://atomicdata.dev/properties/auth/timestamp": timestamp,
            "https://atomicdata.dev/properties/auth/signature": signature,
        });
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(proof.to_string().as_bytes());

        let mut headers = HeaderMap::new();
        headers.insert(
            "Cookie".try_into().unwrap(),
            HeaderValue::from_str(&format!("atomic_session={}", encoded)).unwrap(),
        );
        headers
    }

    /// The staging 401 flood, at the layer it reached the client. A tab keeps
    /// the cookie it was given, that cookie's proof ages past
    /// `AUTH_MAX_AGE_MS`, and every request it makes after that was refused,
    /// including the polls of the public `/server` endpoint that produced the
    /// flood. An aged-out proof now makes the caller nobody instead, so the
    /// rights check is what decides whether the request can be answered.
    #[actix_rt::test]
    async fn a_cookie_whose_proof_aged_out_is_the_public_agent() {
        let appstate = init_test_appstate(&["--domain", "localhost"]).await;
        let server_url = appstate.store.get_server_url().to_string();
        let stale = atomic_lib::utils::now() - atomic_lib::authentication::AUTH_MAX_AGE_MS - 60_000;

        let for_agent =
            get_client_agent(&cookie_header(&server_url, stale), &appstate, &server_url)
                .await
                .expect("a stale cookie does not fail the request");
        assert_eq!(for_agent, ForAgent::Public);
    }

    /// And a cookie whose proof is still fresh authenticates, as it always has.
    #[actix_rt::test]
    async fn a_fresh_cookie_still_authenticates() {
        let appstate = init_test_appstate(&["--domain", "localhost"]).await;
        let server_url = appstate.store.get_server_url().to_string();

        let for_agent = get_client_agent(
            &cookie_header(&server_url, atomic_lib::utils::now()),
            &appstate,
            &server_url,
        )
        .await
        .unwrap();
        assert!(
            matches!(for_agent, ForAgent::AgentSubject(ref s) if s.is_did()),
            "expected the signing agent, got {for_agent:?}"
        );
    }

    #[test]
    fn parse_cookie() {
        let cookie = "atomic_session=eyJodHRwczovL2F0b21pY2RhdGEuZGV2L3Byb3BlcnRpZXMvYXV0aC9hZ2VudCI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTg4My9hZ2VudHMvaGVua2llcGVuayIsImh0dHBzOi8vYXRvbWljZGF0YS5kZXYvcHJvcGVydGllcy9hdXRoL3JlcXVlc3RlZFN1YmplY3QiOiJodHRwOi8vbG9jYWxob3N0Ojk4ODMiLCJodHRwczovL2F0b21pY2RhdGEuZGV2L3Byb3BlcnRpZXMvYXV0aC9wdWJsaWNLZXkiOiJLM3hsa0UxQmFIVXNnRzlYT0h4MVZaVUQ1TGs3ODJua09UcDVHNFN0SDdBPSIsImh0dHBzOi8vYXRvbWljZGF0YS5kZXYvcHJvcGVydGllcy9hdXRoL3RpbWVzdGFtcCI6MTY3NjI4MTU1NjEyNCwiaHR0cHM6Ly9hdG9taWNkYXRhLmRldi9wcm9wZXJ0aWVzL2F1dGgvc2lnbmF0dXJlIjoiMlprdFFWNTNkMVhNUWp4YklSN1pYRkhCMExGT2hHcVlpVlEyRENWc3BkZHVuL3ZHRkhJN3lqdU5jRitIMmpLa0Y0L0R4amEraHdTeUJlZ2ZvTWlxQ1E9PSJ9";

        let mut headermap = HeaderMap::new();
        headermap.insert(
            "Cookie".try_into().unwrap(),
            HeaderValue::from_str(cookie).unwrap(),
        );
        let subject = "http://localhost:9883";
        let out = get_auth_from_cookie(&headermap, subject)
            .expect("Should not return err")
            .expect("Should contain cookie");

        assert_eq!(out.requested_subject, subject);
    }

    #[test]
    fn mutliple_auth_cookies() {
        let cookie = "atomic_session=eyJodHRwczovL2F0b21pY2RhdGEuZGV2L3Byb3BlcnRpZXMvYXV0aC9hZ2VudCI6Imh0dHBzOi8vYXRvbWljZGF0YS5kZXYvYWdlbnRzL1FtZnBSSUJuMkpZRWF0VDBNalNrTU5vQkp6c3R6MTlvcnduVDVvVDJyY1E9IiwiaHR0cHM6Ly9hdG9taWNkYXRhLmRldi9wcm9wZXJ0aWVzL2F1dGgvcmVxdWVzdGVkU3ViamVjdCI6Imh0dHBzOi8vYXRvbWljZGF0YS5kZXYiLCJodHRwczovL2F0b21pY2RhdGEuZGV2L3Byb3BlcnRpZXMvYXV0aC9wdWJsaWNLZXkiOiJRbWZwUklCbjJKWUVhdFQwTWpTa01Ob0JKenN0ejE5b3J3blQ1b1QycmNRPSIsImh0dHBzOi8vYXRvbWljZGF0YS5kZXYvcHJvcGVydGllcy9hdXRoL3RpbWVzdGFtcCI6MTY3NjI4MjU4NDg0NCwiaHR0cHM6Ly9hdG9taWNkYXRhLmRldi9wcm9wZXJ0aWVzL2F1dGgvc2lnbmF0dXJlIjoia1NvLzZQeUdkcnhnbFJFUFdVeUJRVEZxb3RMcmV4L040czRZRFV2d0N0aTl5NEpxWnkwaG92aUtCNkRtMDFCTEdKUU41b3hRdWdveXphSDVIcmVLRHc9PSJ9; atomic_session=eyJodHRwczovL2F0b21pY2RhdGEuZGV2L3Byb3BlcnRpZXMvYXV0aC9hZ2VudCI6Imh0dHBzOi8vYXRvbWljZGF0YS5kZXYvYWdlbnRzL1FtZnBSSUJuMkpZRWF0VDBNalNrTU5vQkp6c3R6MTlvcnduVDVvVDJyY1E9IiwiaHR0cHM6Ly9hdG9taWNkYXRhLmRldi9wcm9wZXJ0aWVzL2F1dGgvcmVxdWVzdGVkU3ViamVjdCI6Imh0dHBzOi8vc3RhZ2luZy5hdG9taWNkYXRhLmRldiIsImh0dHBzOi8vYXRvbWljZGF0YS5kZXYvcHJvcGVydGllcy9hdXRoL3B1YmxpY0tleSI6IlFtZnBSSUJuMkpZRWF0VDBNalNrTU5vQkp6c3R6MTlvcnduVDVvVDJyY1E9IiwiaHR0cHM6Ly9hdG9taWNkYXRhLmRldi9wcm9wZXJ0aWVzL2F1dGgvdGltZXN0YW1wIjoxNjc2MjgzMDQ2ODAzLCJodHRwczovL2F0b21pY2RhdGEuZGV2L3Byb3BlcnRpZXMvYXV0aC9zaWduYXR1cmUiOiIrVmQvc3VTV3U2Ykh4QXV3RUxBRjZ0a3NLNUFuVEpXL3g1L2RZRFFZUTdHS2Y3dXZPdUsycnYyaHVTb2c5SVMxOFppYXdpek8xcjJmVkU1aVdkTytCUT09In0%3D";

        let mut headermap = HeaderMap::new();
        headermap.insert(
            "Cookie".try_into().unwrap(),
            HeaderValue::from_str(cookie).unwrap(),
        );
        let subject = "https://staging.atomicdata.dev";
        let out = get_auth_from_cookie(&headermap, subject)
            .expect("Should not return err")
            .expect("Should contain cookie");

        assert_eq!(out.requested_subject, subject);
    }

    #[test]
    fn irrelevant_cookie() {
        let cookie = "_ga=GA1.1.147665899.1676287441; _ga_XXVM8YFPWJ=GS1.1.1677749978.18.1.1677751673.0.0.0; atomic_session=eyJodHRwczovL2F0b21pY2RhdGEuZGV2L3Byb3BlcnRpZXMvYXV0aC9hZ2VudCI6Imh0dHBzOi8vYXRvbWljZGF0YS5kZXYvYWdlbnRzL1FtZnBSSUJuMkpZRWF0VDBNalNrTU5vQkp6c3R6MTlvcnduVDVvVDJyY1E9IiwiaHR0cHM6Ly9hdG9taWNkYXRhLmRldi9wcm9wZXJ0aWVzL2F1dGgvcmVxdWVzdGVkU3ViamVjdCI6Imh0dHBzOi8vYXRvbWljZGF0YS5kZXYiLCJodHRwczovL2F0b21pY2RhdGEuZGV2L3Byb3BlcnRpZXMvYXV0aC9wdWJsaWNLZXkiOiJRbWZwUklCbjJKWUVhdFQwTWpTa01Ob0JKenN0ejE5b3J3blQ1b1QycmNRPSIsImh0dHBzOi8vYXRvbWljZGF0YS5kZXYvcHJvcGVydGllcy9hdXRoL3RpbWVzdGFtcCI6MTY3Nzc1NDU0OTA1NywiaHR0cHM6Ly9hdG9taWNkYXRhLmRldi9wcm9wZXJ0aWVzL2F1dGgvc2lnbmF0dXJlIjoiZHV1VHhhb2tkb1VRa0MycjZpQ1JCTFBoUFRsM3JCOUFsT2xOTDU0WVExeWpwTjkrbG9YZ1NMQWI0Rzl2UTRPQ3BBRGthVHZLaWlTaWN3K1lndE0wQ0E9PSJ9; atomic_session=eyJodHRwczovL2F0b21pY2RhdGEuZGV2L3Byb3BlcnRpZXMvYXV0aC9hZ2VudCI6Imh0dHBzOi8vYXRvbWljZGF0YS5kZXYvYWdlbnRzL1FtZnBSSUJuMkpZRWF0VDBNalNrTU5vQkp6c3R6MTlvcnduVDVvVDJyY1E9IiwiaHR0cHM6Ly9hdG9taWNkYXRhLmRldi9wcm9wZXJ0aWVzL2F1dGgvcmVxdWVzdGVkU3ViamVjdCI6Imh0dHBzOi8vc3RhZ2luZy5hdG9taWNkYXRhLmRldiIsImh0dHBzOi8vYXRvbWljZGF0YS5kZXYvcHJvcGVydGllcy9hdXRoL3B1YmxpY0tleSI6IlFtZnBSSUJuMkpZRWF0VDBNalNrTU5vQkp6c3R6MTlvcnduVDVvVDJyY1E9IiwiaHR0cHM6Ly9hdG9taWNkYXRhLmRldi9wcm9wZXJ0aWVzL2F1dGgvdGltZXN0YW1wIjoxNjc3NzU4MjkxNTQ3LCJodHRwczovL2F0b21pY2RhdGEuZGV2L3Byb3BlcnRpZXMvYXV0aC9zaWduYXR1cmUiOiJMTlJrRnFUMFJzQ3R6QWpQdDI1bXVjbkQ0WHh3aFRtS3pYYmhXR1FkYWFkK0pJOXVzaEExM0FUK2FBZWxGMUJFVDVWSkVCdldJWkhNOUFaMzR5ejhCQT09In0%3D";

        let mut headermap = HeaderMap::new();
        headermap.insert(
            "Cookie".try_into().unwrap(),
            HeaderValue::from_str(cookie).unwrap(),
        );
        let subject = "https://staging.atomicdata.dev";
        let out = get_auth_from_cookie(&headermap, subject)
            .expect("Should not return err")
            .expect("Should contain cookie");

        assert_eq!(out.requested_subject, subject);
    }

    #[test]
    fn bearer() {
        let token = "eyJodHRwczovL2F0b21pY2RhdGEuZGV2L3Byb3BlcnRpZXMvYXV0aC9hZ2VudCI6Imh0dHBzOi8vYXRvbWljZGF0YS5kZXYvYWdlbnRzL1FtZnBSSUJuMkpZRWF0VDBNalNrTU5vQkp6c3R6MTlvcnduVDVvVDJyY1E9IiwiaHR0cHM6Ly9hdG9taWNkYXRhLmRldi9wcm9wZXJ0aWVzL2F1dGgvcmVxdWVzdGVkU3ViamVjdCI6Imh0dHBzOi8vYXRvbWljZGF0YS5kZXYiLCJodHRwczovL2F0b21pY2RhdGEuZGV2L3Byb3BlcnRpZXMvYXV0aC9wdWJsaWNLZXkiOiJRbWZwUklCbjJKWUVhdFQwTWpTa01Ob0JKenN0ejE5b3J3blQ1b1QycmNRPSIsImh0dHBzOi8vYXRvbWljZGF0YS5kZXYvcHJvcGVydGllcy9hdXRoL3RpbWVzdGFtcCI6MTY3NjI4MjU4NDg0NCwiaHR0cHM6Ly9hdG9taWNkYXRhLmRldi9wcm9wZXJ0aWVzL2F1dGgvc2lnbmF0dXJlIjoia1NvLzZQeUdkcnhnbFJFUFdVeUJRVEZxb3RMcmV4L040czRZRFV2d0N0aTl5NEpxWnkwaG92aUtCNkRtMDFCTEdKUU41b3hRdWdveXphSDVIcmVLRHc9PSJ9";
        let mut headermap = HeaderMap::new();
        headermap.insert(
            "authorization".try_into().unwrap(),
            HeaderValue::from_str(token).unwrap(),
        );
        let subject = "https://atomicdata.dev";
        let out = get_auth_headers(&headermap, subject)
            .expect("Should not return err")
            .expect("Should contain cookie");

        assert_eq!(out.requested_subject, subject);
    }
}
