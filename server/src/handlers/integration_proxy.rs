//! LocalThought catalog and actor-bound OAuth handoff. Credentials stay in host storage.
use crate::{appstate::AppState, context::RequestContext, errors::AtomicServerResult as Result};
use actix_web::{web, HttpRequest, HttpResponse};
use atomic_lib::{
    db::{
        plugin_secret::{PluginSecret, PluginSecretKey},
        trees::Tree,
    },
    Db,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;

pub(super) fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "Could not initialize integration proxy client".into())
}
fn origin() -> Result<String> {
    let value = std::env::var("ATOMIC_INTEGRATION_PROXY_URL")
        .unwrap_or_else(|_| "https://localthought.io".into());
    let u = url::Url::parse(&value).map_err(|_| "Invalid integration proxy URL")?;
    if u.origin().ascii_serialization() != value
        || (u.scheme() != "https"
            && !(u.scheme() == "http" && matches!(u.host_str(), Some("localhost" | "127.0.0.1"))))
    {
        return Err("Integration proxy must be an HTTPS origin (or localhost for testing)".into());
    }
    Ok(value)
}
fn random_id() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}
fn sign(secret: &str, text: &str) -> String {
    URL_SAFE_NO_PAD.encode(ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes()),
        text.as_bytes(),
    ))
}
async fn platforms(base: &str) -> Result<Vec<String>> {
    let response = client()?
        .get(format!("{base}/catalog"))
        .send()
        .await
        .map_err(|_| "Could not reach integration catalog")?;
    if !response.status().is_success() {
        return Err("Integration catalog is unavailable".into());
    }
    let names: Vec<String> = response
        .json()
        .await
        .map_err(|_| "Invalid integration catalog")?;
    if names.len() > 200
        || names.iter().any(|s| {
            s.is_empty()
                || s.len() > 80
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    {
        return Err("Invalid catalog platform identifier".into());
    }
    Ok(names)
}
pub async fn catalog() -> Result<HttpResponse> {
    let base = origin()?;
    Ok(HttpResponse::Ok().json(json!({"platforms": platforms(&base).await?, "origin": base})))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Start {
    drive: String,
    platform: String,
    return_url: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Connection {
    pub(super) drive: String,
    pub(super) actor: String,
    pub(super) platform: String,
    pub(super) origin: String,
    pub(super) expires: i64,
    pub(super) ready: bool,
}
fn key(id: &str) -> String {
    format!("integration-proxy/v1/{id}")
}
fn put(db: &Db, id: &str, value: &Connection) -> Result<()> {
    db.kv.insert(
        Tree::PluginMeta,
        key(id).as_bytes(),
        &serde_json::to_vec(value).map_err(|_| "Could not encode connection")?,
    )?;
    db.flush()?;
    Ok(())
}
fn get(db: &Db, id: &str) -> Result<Connection> {
    let bytes = db
        .kv
        .get(Tree::PluginMeta, key(id).as_bytes())?
        .ok_or("Connection not found")?;
    serde_json::from_slice(&bytes).map_err(|_| "Invalid connection".into())
}
pub(super) fn secret_key(c: &Connection, id: &str) -> PluginSecretKey {
    PluginSecretKey::new(&c.drive, &format!("integration-proxy:{id}"), "connection")
}
fn owned(c: &Connection, drive: &str, actor: &str) -> Result<()> {
    if c.drive != drive || c.actor != actor {
        return Err("This connection belongs to another drive or agent".into());
    }
    Ok(())
}
fn return_url(raw: &str) -> Result<url::Url> {
    let u = url::Url::parse(raw).map_err(|_| "Invalid return URL")?;
    let allowed = std::env::var("ATOMIC_INTEGRATION_FRONTEND_ORIGIN")
        .map_err(|_| "Configure ATOMIC_INTEGRATION_FRONTEND_ORIGIN on this server")?;
    if u.origin().ascii_serialization() != allowed
        || u.path() != "/app/integrations"
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
        || u.query().is_some()
    {
        return Err("Return URL must be the configured frontend integrations page".into());
    }
    Ok(u)
}
pub async fn start(
    app: web::Data<AppState>,
    body: web::Json<Start>,
    req: HttpRequest,
    ctx: RequestContext,
) -> Result<HttpResponse> {
    let actor = super::plugin_schedule::authorize(&app, &req, &ctx, &body.drive)
        .await?
        .to_string();
    let base = origin()?;
    if !platforms(&base).await?.contains(&body.platform) {
        return Err("Platform is not in the integration catalog".into());
    }
    let secret = std::env::var("TENANT_SECRET")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("Configure TENANT_SECRET on this server to connect accounts")?;
    let tenant = secret
        .split_once('.')
        .and_then(|(id, _)| URL_SAFE_NO_PAD.decode(id).ok())
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or("Invalid tenant secret configuration")?;
    let mut callback = return_url(&body.return_url)?;
    let id = random_id();
    callback
        .query_pairs_mut()
        .append_pair("integration_state", &id)
        .append_pair("platform", &body.platform);
    #[derive(Deserialize)]
    struct Challenge {
        ts: u64,
        nonce: String,
        challenge: String,
    }
    let response = client()?
        .get(format!("{base}/session"))
        .send()
        .await
        .map_err(|_| "Could not obtain integration challenge")?;
    if !response.status().is_success() {
        return Err("Integration challenge is unavailable".into());
    }
    let challenge: Challenge = response
        .json()
        .await
        .map_err(|_| "Invalid integration challenge")?;
    let mut connect =
        url::Url::parse(&format!("{base}/connect")).map_err(|_| "Invalid proxy URL")?;
    connect
        .query_pairs_mut()
        .append_pair("redirect_uri", callback.as_str())
        .append_pair("platform", &body.platform)
        .append_pair("ts", &challenge.ts.to_string())
        .append_pair("nonce", &challenge.nonce)
        .append_pair("challenge", &challenge.challenge)
        .append_pair("tenant_id", &tenant)
        .append_pair("user_id", &actor)
        .append_pair("user_id_sig", &sign(&secret, &actor))
        .append_pair("response", &sign(&secret, &challenge.challenge));
    put(
        &app.store,
        &id,
        &Connection {
            drive: body.drive.clone(),
            actor,
            platform: body.platform.clone(),
            origin: base,
            expires: atomic_lib::utils::now() + 600_000,
            ready: false,
        },
    )?;
    Ok(HttpResponse::Ok().json(json!({"url":connect.as_str(),"state":id})))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Finish {
    drive: String,
    state: String,
    connection_code: String,
}
pub async fn finish(
    app: web::Data<AppState>,
    body: web::Json<Finish>,
    req: HttpRequest,
    ctx: RequestContext,
) -> Result<HttpResponse> {
    let actor = super::plugin_schedule::authorize(&app, &req, &ctx, &body.drive)
        .await?
        .to_string();
    let _lock = app.store.lock_plugin(&key(&body.state)).await;
    let mut c = get(&app.store, &body.state)?;
    owned(&c, &body.drive, &actor)?;
    if c.ready
        || c.expires < atomic_lib::utils::now()
        || body.connection_code.is_empty()
        || body.connection_code.len() > 4096
    {
        return Err("Invalid, expired or already completed connection request".into());
    }
    app.store.set_plugin_secret(
        &secret_key(&c, &body.state),
        &PluginSecret::new(
            body.connection_code.clone(),
            vec![c.origin.clone()],
            atomic_lib::utils::now(),
        ),
    )?;
    c.ready = true;
    put(&app.store, &body.state, &c)?;
    Ok(HttpResponse::Ok().json(json!({"connection":body.state,"platform":c.platform})))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Fetch {
    drive: String,
    connection: String,
    constants: std::collections::BTreeMap<String, String>,
    calendar_range: Option<super::integration_proxy_sync::CalendarRange>,
}
pub async fn fetch_records(
    app: web::Data<AppState>,
    body: web::Json<Fetch>,
    req: HttpRequest,
    ctx: RequestContext,
) -> Result<HttpResponse> {
    let actor = super::plugin_schedule::authorize(&app, &req, &ctx, &body.drive)
        .await?
        .to_string();
    let _lock = app.store.lock_plugin(&key(&body.connection)).await;
    let c = get(&app.store, &body.connection)?;
    owned(&c, &body.drive, &actor)?;
    if !c.ready {
        return Err("Finish connecting your account first".into());
    }
    let data = super::integration_proxy_sync::sync(
        app.store.clone(),
        c,
        body.connection.clone(),
        body.constants.clone(),
        body.calendar_range.as_ref(),
    )
    .await?;
    Ok(HttpResponse::Ok().json(data))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn connection_is_bound_to_actor_and_drive() {
        let c = Connection {
            drive: "a".into(),
            actor: "b".into(),
            platform: "github-issues".into(),
            origin: "https://localthought.io".into(),
            expires: 0,
            ready: true,
        };
        assert!(owned(&c, "a", "b").is_ok());
        assert!(owned(&c, "other", "b").is_err());
        assert!(owned(&c, "a", "other").is_err());
    }
    #[test]
    fn signatures_match_proxy_hmac_contract() {
        assert_eq!(
            sign("key", "The quick brown fox jumps over the lazy dog"),
            "97yD9DBThCSxMpjmqm-xQ-9NWaFJRhdZl0edvC0aPNg"
        );
    }
}

#[derive(Deserialize)]
pub struct PlatformQuery {
    platform: String,
}
pub async fn platform(query: web::Query<PlatformQuery>) -> Result<HttpResponse> {
    let base = origin()?;
    if !platforms(&base).await?.contains(&query.platform) {
        return Err("Platform is not in the catalog".into());
    }
    Ok(HttpResponse::Ok()
        .json(super::integration_proxy_sync::describe(&base, &query.platform).await?))
}
