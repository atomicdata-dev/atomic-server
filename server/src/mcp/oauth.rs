//! The OAuth 2.1 authorization server for the hosted MCP endpoint.
//!
//! Flow, as MCP clients (claude.ai, Claude Code, Cursor) run it:
//!
//! 1. `POST /mcp` answers 401 with a `WWW-Authenticate` header pointing at
//!    `/.well-known/oauth-protected-resource` (RFC 9728), which names this
//!    node as the authorization server.
//! 2. The client registers itself (`POST /oauth/register`, RFC 7591). Its id is
//!    the registration, signed.
//! 3. The browser goes to `GET /oauth/authorize`, which sends the person to the
//!    app's consent page. There they pick drives and Allow. The app asks for an
//!    issued agent (`POST /oauth/agent`), gives it read rights on those drives
//!    itself, as the person, and completes with `POST /oauth/approve`, which
//!    returns the URL to send the browser back to, carrying the code.
//! 4. `POST /oauth/token` swaps the code (with PKCE) for tokens.
//!
//! Approval is signed by the person's own agent, like any write. What a token
//! may reach is what the ACLs give the issued agent, so revoking is removing
//! it from them (Connected apps), and the node never signs as the person.

use actix_web::{web, HttpRequest, HttpResponse};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::HashMap, sync::Mutex};

use super::tokens::{self, Client, Code, Grant};
use crate::{
    appstate::AppState,
    errors::{AtomicServerError, AtomicServerResult},
    helpers::get_client_agent_for_request,
};
use atomic_lib::agents::ForAgent;

/// The MCP endpoint's URL, which is also the OAuth `resource`.
pub fn resource_url(origin: &str) -> String {
    format!("{origin}/mcp")
}

/// Where the person approves: the app, which is this server unless told otherwise.
fn app_url(appstate: &AppState, origin: &str) -> String {
    appstate
        .config
        .opts
        .app_url
        .as_deref()
        .unwrap_or(origin)
        .trim_end_matches('/')
        .to_string()
}

pub async fn protected_resource_metadata(
    appstate: web::Data<AppState>,
    req: HttpRequest,
) -> HttpResponse {
    let origin = crate::context::RequestContext::new(&req, &appstate).origin;

    HttpResponse::Ok().json(json!({
        "resource": resource_url(&origin),
        "authorization_servers": [origin],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["read", "write"],
        "resource_name": "Atomic Data",
    }))
}

pub async fn authorization_server_metadata(
    appstate: web::Data<AppState>,
    req: HttpRequest,
) -> HttpResponse {
    let origin = crate::context::RequestContext::new(&req, &appstate).origin;

    HttpResponse::Ok().json(json!({
        "issuer": origin,
        "authorization_endpoint": format!("{origin}/oauth/authorize"),
        "token_endpoint": format!("{origin}/oauth/token"),
        "registration_endpoint": format!("{origin}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["read", "write"],
    }))
}

/// A redirect URI a client may register: HTTPS, plain HTTP only to this
/// machine (native apps), or an app's own scheme. Never a scheme that runs
/// code in the browser, and never a fragment (RFC 6749 3.1.2).
fn valid_redirect_uri(uri: &str) -> bool {
    let Ok(url) = url::Url::parse(uri) else {
        return false;
    };
    if url.fragment().is_some() {
        return false;
    }
    match url.scheme() {
        "https" => url.host_str().is_some(),
        "http" => matches!(
            url.host_str(),
            Some("localhost") | Some("127.0.0.1") | Some("[::1]")
        ),
        "javascript" | "data" | "file" | "vbscript" | "blob" | "about" | "ftp" | "ws" | "wss" => {
            false
        }
        _ => true,
    }
}

/// Whether a requested `scope` includes editing.
fn wants_write(scope: &str) -> bool {
    scope.split_whitespace().any(|s| s == "write")
}

fn oauth_error(
    status: actix_web::http::StatusCode,
    error: &str,
    description: &str,
) -> HttpResponse {
    HttpResponse::build(status)
        .insert_header(("Cache-Control", "no-store"))
        .json(json!({ "error": error, "error_description": description }))
}

fn bad(error: &str, description: &str) -> HttpResponse {
    oauth_error(actix_web::http::StatusCode::BAD_REQUEST, error, description)
}

#[derive(Deserialize)]
pub struct RegisterBody {
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
}

/// Dynamic client registration (RFC 7591). Public clients only.
pub async fn register(
    appstate: web::Data<AppState>,
    body: web::Json<RegisterBody>,
) -> HttpResponse {
    let body = body.into_inner();

    if body.redirect_uris.is_empty()
        || body.redirect_uris.len() > 10
        || !body.redirect_uris.iter().all(|u| valid_redirect_uri(u))
    {
        return bad(
            "invalid_redirect_uri",
            "Give one to ten redirect URIs: https, http on localhost, or an app scheme.",
        );
    }
    let name: String = body
        .client_name
        .as_deref()
        .unwrap_or("MCP client")
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect();
    let client = Client {
        name: name.clone(),
        redirect_uris: body.redirect_uris.clone(),
    };
    let client_id = match tokens::sign(&appstate, tokens::CLIENT, tokens::CLIENT_TTL, &client) {
        Ok(id) => id,
        Err(e) => return bad("server_error", &e),
    };

    HttpResponse::Created()
        .insert_header(("Cache-Control", "no-store"))
        .json(json!({
            "client_id": client_id,
            "client_name": name,
            "redirect_uris": body.redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_id_issued_at": tokens::now(),
        }))
}

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    /// What the client asks for: `read`, or `read write` to also edit. The
    /// person decides on the consent page; this only sets the default.
    scope: Option<String>,
    state: Option<String>,
}

/// Sends the browser to the app's consent page. An unknown client or
/// redirect URI is answered here, never redirected to, so this cannot be
/// used as an open redirect.
pub async fn authorize(
    appstate: web::Data<AppState>,
    query: web::Query<AuthorizeQuery>,
    req: HttpRequest,
) -> HttpResponse {
    let origin = crate::context::RequestContext::new(&req, &appstate).origin;
    let q = query.into_inner();
    let (Some(client_id), Some(redirect_uri)) = (q.client_id.as_deref(), q.redirect_uri.as_deref())
    else {
        return HttpResponse::BadRequest().body("Missing client_id or redirect_uri");
    };
    let client: Client = match tokens::verify(&appstate, tokens::CLIENT, client_id) {
        Ok(c) => c,
        Err(e) => return HttpResponse::BadRequest().body(format!("Unknown client: {e}")),
    };
    if !client.redirect_uris.iter().any(|u| u == redirect_uri) {
        return HttpResponse::BadRequest().body("That redirect_uri was not registered");
    }

    let back = |error: &str, description: &str| {
        let mut url = url::Url::parse(redirect_uri).expect("registered URIs parse");
        url.query_pairs_mut()
            .append_pair("error", error)
            .append_pair("error_description", description);
        if let Some(state) = &q.state {
            url.query_pairs_mut().append_pair("state", state);
        }
        HttpResponse::Found()
            .insert_header(("Location", url.to_string()))
            .finish()
    };

    if q.response_type.as_deref() != Some("code") {
        return back("unsupported_response_type", "Only response_type=code");
    }
    let Some(challenge) = q.code_challenge.as_deref().filter(|c| !c.is_empty()) else {
        return back("invalid_request", "PKCE code_challenge is required");
    };
    if q.code_challenge_method.as_deref() != Some("S256") {
        return back("invalid_request", "code_challenge_method must be S256");
    }

    let mut url = match url::Url::parse(&format!(
        "{}/app/authorize-mcp",
        app_url(&appstate, &origin)
    )) {
        Ok(u) => u,
        Err(_) => return HttpResponse::InternalServerError().body("Bad app URL"),
    };
    {
        let mut pairs = url.query_pairs_mut();
        pairs
            .append_pair("server", &origin)
            .append_pair("client_id", client_id)
            .append_pair("client_name", &client.name)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("code_challenge", challenge);
        if q.scope.as_deref().is_some_and(wants_write) {
            pairs.append_pair("scope", "read write");
        }
        if let Some(state) = &q.state {
            pairs.append_pair("state", state);
        }
    }

    HttpResponse::Found()
        .insert_header(("Location", url.to_string()))
        .insert_header(("Cache-Control", "no-store"))
        .finish()
}

/// The signed-in person behind a request, or 401. Signed like any write.
async fn person(
    appstate: &AppState,
    req: &HttpRequest,
    body: &[u8],
    origin: &str,
) -> AtomicServerResult<String> {
    let path_and_query = req
        .head()
        .uri
        .path_and_query()
        .ok_or("Path must be given")?
        .to_string();
    let signed_subject = atomic_lib::Subject::from_raw(&path_and_query, None).resolve(origin);
    let agent = get_client_agent_for_request(req, body, appstate, &signed_subject).await?;
    crate::helpers::enforce_write_rate_limit(appstate, req, &agent)?;

    match agent {
        ForAgent::AgentSubject(subject) => Ok(subject.to_string()),
        _ => Err(AtomicServerError::bad_request("Sign in to approve an app")),
    }
}

fn parse<T: for<'a> Deserialize<'a>>(raw: &[u8]) -> AtomicServerResult<T> {
    serde_json::from_slice(raw)
        .map_err(|e| AtomicServerError::bad_request(format!("Invalid JSON body: {e}")))
}

fn client_of(appstate: &AppState, client_id: &str) -> AtomicServerResult<Client> {
    tokens::verify(appstate, tokens::CLIENT, client_id)
        .map_err(|e| AtomicServerError::bad_request(format!("Unknown client: {e}")))
}

#[derive(Deserialize)]
struct AgentBody {
    client_id: String,
}

#[derive(Serialize)]
struct AgentReply {
    agent: String,
    nonce: String,
}

/// Step one of approving: a fresh issued agent for this person and client,
/// which the app then grants rights to before calling [approve].
pub async fn issue_agent(
    appstate: web::Data<AppState>,
    raw: web::Bytes,
    req: HttpRequest,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    let person = person(&appstate, &req, &raw, &context.origin).await?;
    let body: AgentBody = parse(&raw)?;
    client_of(&appstate, &body.client_id)?;

    let mut random = [0u8; 16];
    use ring::rand::SecureRandom;
    ring::rand::SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| "Could not make a nonce")?;
    let nonce = URL_SAFE_NO_PAD.encode(random);
    let agent = tokens::issued_agent(&appstate, &person, &body.client_id, &nonce, None)
        .map_err(AtomicServerError::bad_request)?;

    Ok(HttpResponse::Ok().json(AgentReply {
        agent: agent.subject.to_string(),
        nonce,
    }))
}

#[derive(Deserialize)]
struct ApproveBody {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    nonce: String,
    /// The person let the client edit, not only read.
    #[serde(default)]
    write: bool,
    #[serde(default)]
    state: Option<String>,
}

/// Step two: the person allowed it, and the app has granted the issued agent.
/// Answers with where to send the browser, carrying the authorization code.
pub async fn approve(
    appstate: web::Data<AppState>,
    raw: web::Bytes,
    req: HttpRequest,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    let person = person(&appstate, &req, &raw, &context.origin).await?;
    let body: ApproveBody = parse(&raw)?;
    let client = client_of(&appstate, &body.client_id)?;

    if !client.redirect_uris.contains(&body.redirect_uri) {
        return Err(AtomicServerError::bad_request(
            "That redirect_uri was not registered",
        ));
    }
    let agent = tokens::issued_agent(
        &appstate,
        &person,
        &body.client_id,
        &body.nonce,
        Some(&client.name),
    )
    .map_err(AtomicServerError::bad_request)?;
    // The name the person sees under Connected apps. Only an agent may edit
    // its own Agent resource, so the node, which can derive this key, makes
    // it. Cosmetic: without it the app shows as a key, so a failure is logged
    // and the approval goes on.
    match agent.to_resource() {
        Ok(mut resource) => {
            if let Err(e) = resource.save_locally(&appstate.store).await {
                tracing::warn!("Could not name issued agent {}: {e}", agent.subject);
            }
        }
        Err(e) => tracing::warn!("Could not build issued agent resource: {e}"),
    }
    let code = tokens::sign(
        &appstate,
        tokens::CODE,
        tokens::CODE_TTL,
        &Code {
            agent: agent.subject.to_string(),
            client_id: body.client_id,
            redirect_uri: body.redirect_uri.clone(),
            challenge: body.code_challenge,
            person,
            nonce: body.nonce,
            write: body.write,
        },
    )
    .map_err(AtomicServerError::bad_request)?;

    let mut url = url::Url::parse(&body.redirect_uri)
        .map_err(|_| AtomicServerError::bad_request("Bad redirect_uri"))?;
    url.query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("iss", &context.origin);
    if let Some(state) = body.state {
        url.query_pairs_mut().append_pair("state", &state);
    }

    Ok(HttpResponse::Ok().json(json!({ "redirect_url": url.to_string() })))
}

#[derive(Deserialize)]
pub struct TokenForm {
    grant_type: String,
    code: Option<String>,
    code_verifier: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    refresh_token: Option<String>,
    /// RFC 8707: which resource the token is for. Only this node's `/mcp`.
    resource: Option<String>,
}

/// Authorization codes already redeemed, until they would have expired anyway.
fn spent() -> &'static Mutex<HashMap<String, i64>> {
    static SPENT: std::sync::OnceLock<Mutex<HashMap<String, i64>>> = std::sync::OnceLock::new();
    SPENT.get_or_init(Default::default)
}

/// True the first time a code is redeemed, false ever after.
fn redeem_once(code: &str) -> bool {
    let now = tokens::now();
    let mut spent = spent().lock().unwrap_or_else(|e| e.into_inner());
    spent.retain(|_, exp| *exp > now);
    spent
        .insert(code.to_string(), now + tokens::CODE_TTL)
        .is_none()
}

fn pkce_matches(verifier: &str, challenge: &str) -> bool {
    let digest = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(digest.as_ref());

    // Constant time enough for a value the client already holds: compare hashes.
    blake3::hash(computed.as_bytes()) == blake3::hash(challenge.as_bytes())
}

fn token_reply(appstate: &AppState, grant: &Grant) -> HttpResponse {
    let sign = |kind, ttl| tokens::sign(appstate, kind, ttl, grant);
    match (
        sign(tokens::ACCESS, tokens::ACCESS_TTL),
        sign(tokens::REFRESH, tokens::REFRESH_TTL),
    ) {
        (Ok(access), Ok(refresh)) => HttpResponse::Ok()
            .insert_header(("Cache-Control", "no-store"))
            .json(json!({
                "access_token": access,
                "token_type": "Bearer",
                "expires_in": tokens::ACCESS_TTL,
                "refresh_token": refresh,
                "scope": grant.scope(),
            })),
        (Err(e), _) | (_, Err(e)) => bad("server_error", &e),
    }
}

pub async fn token(
    appstate: web::Data<AppState>,
    form: web::Form<TokenForm>,
    req: HttpRequest,
) -> HttpResponse {
    let f = form.into_inner();
    let origin = crate::context::RequestContext::new(&req, &appstate).origin;

    if let Some(resource) = f.resource.as_deref() {
        if resource != resource_url(&origin) {
            return bad(
                "invalid_target",
                "This node only issues tokens for its own /mcp",
            );
        }
    }

    match f.grant_type.as_str() {
        "authorization_code" => {
            let (Some(code), Some(verifier), Some(redirect_uri), Some(client_id)) =
                (&f.code, &f.code_verifier, &f.redirect_uri, &f.client_id)
            else {
                return bad(
                    "invalid_request",
                    "code, code_verifier, redirect_uri and client_id are required",
                );
            };
            let claims: Code = match tokens::verify(&appstate, tokens::CODE, code) {
                Ok(c) => c,
                Err(e) => return bad("invalid_grant", &e),
            };
            if &claims.client_id != client_id || &claims.redirect_uri != redirect_uri {
                return bad("invalid_grant", "The code was issued to someone else");
            }
            if !pkce_matches(verifier, &claims.challenge) {
                return bad("invalid_grant", "PKCE verification failed");
            }
            if !redeem_once(code) {
                return bad("invalid_grant", "That code was already used");
            }

            token_reply(
                &appstate,
                &Grant {
                    agent: claims.agent,
                    client_id: claims.client_id,
                    person: claims.person,
                    nonce: claims.nonce,
                    write: claims.write,
                },
            )
        }
        "refresh_token" => {
            let Some(refresh) = &f.refresh_token else {
                return bad("invalid_request", "refresh_token is required");
            };
            match tokens::verify::<Grant>(&appstate, tokens::REFRESH, refresh) {
                Ok(grant) => token_reply(&appstate, &grant),
                Err(e) => bad("invalid_grant", &e),
            }
        }
        _ => bad(
            "unsupported_grant_type",
            "Use authorization_code or refresh_token",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_safe_redirect_uris_may_be_registered() {
        for ok in [
            "https://claude.ai/api/mcp/auth_callback",
            "http://localhost:6274/oauth/callback",
            "http://127.0.0.1:33418/callback",
            "cursor://anysphere.cursor-retrieval/oauth/user-atomic/callback",
        ] {
            assert!(valid_redirect_uri(ok), "{ok}");
        }
        for bad in [
            "http://example.com/callback",
            "javascript:alert(1)",
            "data:text/html,hi",
            "https://claude.ai/cb#fragment",
            "not a uri",
            "",
        ] {
            assert!(!valid_redirect_uri(bad), "{bad}");
        }
    }

    #[test]
    fn pkce_checks_the_s256_challenge() {
        // The example from RFC 7636, appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        assert!(pkce_matches(verifier, challenge));
        assert!(!pkce_matches("another", challenge));
    }

    #[test]
    fn a_code_is_redeemed_once() {
        assert!(redeem_once("code-a-unit-test"));
        assert!(!redeem_once("code-a-unit-test"));
    }

    #[test]
    fn write_is_only_asked_for_by_scope() {
        assert!(wants_write("read write"));
        assert!(wants_write("write"));
        assert!(!wants_write("read"));
        assert!(!wants_write("overwrite"));
    }
}
