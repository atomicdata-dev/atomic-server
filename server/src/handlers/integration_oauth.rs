//! Host-owned authorization and discovery. Provider tokens never enter graph data,
//! browser responses, plugin code, or logs. Signed completion binds OAuth to its actor.
use crate::oauth::{
    exchange::response_json,
    provider::{self, Provider},
};
use crate::{
    appstate::AppState, context::RequestContext, errors::AtomicServerResult as Result,
    plugins::js_runtime::StoreHost,
};
use actix_web::{web, HttpResponse};
use atomic_lib::{
    db::{
        plugin_secret::{PluginSecret, PluginSecretKey},
        trees::Tree,
    },
    Db,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
const TTL: i64 = 10 * 60 * 1000;
fn now() -> i64 {
    atomic_lib::utils::now()
}
fn random_id() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn key(kind: &str, id: &str) -> String {
    format!("integration-oauth/v1/{kind}/{id}")
}
fn put<T: Serialize>(db: &Db, kind: &str, id: &str, data: &T) -> Result<()> {
    db.kv.insert(
        Tree::PluginMeta,
        key(kind, id).as_bytes(),
        &serde_json::to_vec(data).map_err(|e| e.to_string())?,
    )?;
    db.flush()?;
    Ok(())
}
fn get<T: serde::de::DeserializeOwned>(db: &Db, kind: &str, id: &str) -> Result<T> {
    let b = db
        .kv
        .get(Tree::PluginMeta, key(kind, id).as_bytes())?
        .ok_or("Connection or sign-in request not found")?;
    Ok(serde_json::from_slice(&b).map_err(|e| e.to_string())?)
}
fn remove(db: &Db, kind: &str, id: &str) -> Result<()> {
    db.kv.remove(Tree::PluginMeta, key(kind, id).as_bytes())?;
    db.flush()?;
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    drive: String,
    #[serde(default)]
    connection: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct Pending {
    #[serde(default)]
    service: Option<String>,
    drive: String,
    actor: String,
    expires: i64,
    connection: Option<String>,
    provider: String,
}
#[derive(Serialize, Deserialize)]
struct Connection {
    id: String,
    drive: String,
    actor: String,
    provider: String,
    #[serde(rename = "workspace")]
    account: String,
    name: String,
}
fn credential(c: &Connection) -> PluginSecretKey {
    PluginSecretKey::new(
        &c.drive,
        &format!("integration-connection:{}", c.id),
        &c.provider,
    )
}
fn owned(c: &Connection, provider: &str, drive: &str, actor: &str) -> Result<()> {
    if c.drive != drive || c.actor != actor || c.provider != provider {
        return Err("This connection belongs to a different workspace or agent".into());
    }
    Ok(())
}
async fn actor(
    app: &AppState,
    req: &actix_web::HttpRequest,
    ctx: &RequestContext,
    drive: &str,
) -> Result<String> {
    Ok(super::plugin_schedule::authorize(app, req, ctx, drive)
        .await?
        .to_string())
}
fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "Could not initialize provider client")?)
}
fn authorized_request(
    db: &Db,
    c: &Connection,
    provider: &Provider,
    method: reqwest::Method,
) -> Result<reqwest::RequestBuilder> {
    let mut request = client()?.request(method, provider.api_url(&provider.discovery.path)?);
    for (name, value) in &provider.api_headers {
        request = request.header(name, value);
    }
    db.use_plugin_secret(
        &credential(c),
        provider.api_origin.as_str(),
        now(),
        |token| request.header("Authorization", token),
    )?
    .ok_or_else(|| "Provider connection is disconnected. Reconnect to continue.".into())
}
pub async fn list(
    provider_id: web::Path<String>,
    app: web::Data<AppState>,
    body: web::Json<Target>,
    req: actix_web::HttpRequest,
    ctx: RequestContext,
) -> Result<HttpResponse> {
    let provider = provider::load(&provider_id)?;
    let a = actor(&app, &req, &ctx, &body.drive).await?;
    let mut connections = Vec::new();
    for entry in app
        .store
        .kv
        .scan_prefix(Tree::PluginMeta, key("connection", "").as_bytes())
    {
        let (_, v) = entry?;
        let c: Connection = serde_json::from_slice(&v).map_err(|e| e.to_string())?;
        if owned(&c, &provider.id, &body.drive, &a).is_ok() {
            connections.push(c);
        }
    }
    Ok(HttpResponse::Ok()
        .json(json!({"configured":crate::oauth::remote::Remote::from_env().map(|r|r.is_some()||provider.config().is_ok()).unwrap_or(false),"connections":connections})))
}
pub async fn start(
    provider_id: web::Path<String>,
    app: web::Data<AppState>,
    body: web::Json<Target>,
    req: actix_web::HttpRequest,
    ctx: RequestContext,
) -> Result<HttpResponse> {
    let provider = provider::load(&provider_id)?;
    let a = actor(&app, &req, &ctx, &body.drive).await?;
    let remote = crate::oauth::remote::Remote::from_env()?;
    let config = if remote.is_none() {
        Some(provider.config()?)
    } else {
        None
    };
    if let Some(id) = &body.connection {
        owned(
            &get::<Connection>(&app.store, "connection", id)?,
            &provider.id,
            &body.drive,
            &a,
        )?;
    }
    // One active login per provider, actor and drive limits pending state across restarts.
    let slot =
        serde_json::to_string(&json!([provider.id, body.drive, a])).map_err(|e| e.to_string())?;
    let _lock = app.store.lock_plugin(&format!("oauth-start:{slot}")).await;
    if let Ok(old) = get::<String>(&app.store, "active", &slot) {
        remove(&app.store, "pending", &old)?;
        app.store
            .delete_plugin_secret(&pending_secret(&body.drive, &old))?;
    }
    let state = random_id();
    let managed = if let Some(service) = &remote {
        let ticket = service
            .start(
                provider.id.clone(),
                a.clone(),
                body.drive.clone(),
                state.clone(),
            )
            .await?;
        app.store.set_plugin_secret(
            &pending_secret(&body.drive, &state),
            &PluginSecret::new(
                serde_json::to_string(&ticket).map_err(|_| "Invalid authorization ticket")?,
                vec![service.origin.clone()],
                now(),
            ),
        )?;
        Some(ticket.url)
    } else {
        None
    };
    put(
        &app.store,
        "pending",
        &state,
        &Pending {
            service: remote.as_ref().map(|r| r.origin.clone()),
            drive: body.drive.clone(),
            actor: a,
            expires: now() + TTL,
            connection: body.connection.clone(),
            provider: provider.id.clone(),
        },
    )?;
    put(&app.store, "active", &slot, &state)?;
    if let Some(url) = managed {
        return Ok(HttpResponse::Ok().json(json!({"url":url,"state":state,"mode":"managed"})));
    }
    let config = config.ok_or("Authorization configuration missing")?;
    let mut url = provider.authorization_url.clone();
    url.query_pairs_mut().extend_pairs([
        ("client_id", config.client_id.as_str()),
        ("redirect_uri", config.redirect_uri.as_str()),
        ("response_type", "code"),
        ("state", state.as_str()),
    ]);
    url.query_pairs_mut().extend_pairs(
        provider
            .authorization_params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str())),
    );
    Ok(HttpResponse::Ok().json(json!({"url":url.as_str(),"state":state})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finish {
    drive: String,
    state: String,
    code: Option<String>,
    error: Option<String>,
}
fn pending_secret(drive: &str, state: &str) -> PluginSecretKey {
    PluginSecretKey::new(drive, &format!("oauth-pending:{state}"), "handoff")
}
fn validate_pending(p: &Pending, drive: &str, actor: &str, at: i64) -> Result<()> {
    if p.drive != drive || p.actor != actor {
        return Err("Sign-in belongs to another workspace or agent".into());
    }
    if at >= p.expires {
        return Err("Sign-in expired. Connect the provider again.".into());
    }
    Ok(())
}
pub async fn finish(
    provider_id: web::Path<String>,
    app: web::Data<AppState>,
    body: web::Json<Finish>,
    req: actix_web::HttpRequest,
    ctx: RequestContext,
) -> Result<HttpResponse> {
    let provider = provider::load(&provider_id)?;
    let a = actor(&app, &req, &ctx, &body.drive).await?;
    let _lock = app
        .store
        .lock_plugin(&format!("oauth-finish:{}", body.state))
        .await;
    let p: Pending = get(&app.store, "pending", &body.state)?;
    validate_pending(&p, &body.drive, &a, now())?;
    if p.provider != provider.id {
        return Err("Sign-in belongs to another provider".into());
    }
    let data = if let Some(origin) = &p.service {
        let service = crate::oauth::remote::Remote::from_env()?
            .ok_or("Authorization service is no longer configured")?;
        if service.origin != *origin {
            return Err("Authorization service changed. Connect again.".into());
        }
        let raw = app
            .store
            .use_plugin_secret(
                &pending_secret(&body.drive, &body.state),
                origin,
                now(),
                |v| v.to_owned(),
            )?
            .ok_or("Authorization ticket unavailable. Connect again.")?;
        let ticket: crate::oauth::remote::Ticket =
            serde_json::from_str(&raw).map_err(|_| "Invalid authorization ticket")?;
        let result = service
            .redeem(
                &ticket,
                provider.id.clone(),
                a.clone(),
                body.drive.clone(),
                body.state.clone(),
            )
            .await?;
        if result["pending"] == true {
            return Ok(HttpResponse::Ok().json(json!({"pending":true})));
        }
        remove(&app.store, "pending", &body.state)?;
        app.store
            .delete_plugin_secret(&pending_secret(&body.drive, &body.state))?;
        if result.get("error").is_some() {
            return Err("Provider sign-in did not complete. Connect again.".into());
        }
        result
            .get("credentials")
            .cloned()
            .ok_or("Authorization service returned no credentials")?
    } else {
        remove(&app.store, "pending", &body.state)?;
        if body.error.is_some() {
            return Err("Provider sign-in was cancelled. You can try again.".into());
        }
        let code = body
            .code
            .as_ref()
            .filter(|s| !s.is_empty() && s.len() < 4096)
            .ok_or("Provider did not return an authorization code")?;
        let config = provider.config()?;
        crate::oauth::exchange::exchange_code(
            &provider,
            &config.client_id,
            &config.client_secret,
            &config.redirect_uri,
            code,
        )
        .await?
    };
    let token = data
        .pointer(&provider.access_token_pointer)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("Provider did not return a token")?;
    let account = provider
        .account_id(&data)
        .ok_or("Provider did not identify the account")?
        .to_owned();
    let c = if let Some(id) = p.connection {
        let old: Connection = get(&app.store, "connection", &id)?;
        owned(&old, &provider.id, &body.drive, &a)?;
        if old.account != account {
            return Err("Choose the original provider account when reconnecting".into());
        }
        old
    } else {
        Connection {
            id: random_id(),
            drive: body.drive.clone(),
            actor: a,
            provider: provider.id.clone(),
            account,
            name: provider.account_name(&data).to_owned(),
        }
    };
    app.store.set_plugin_secret(
        &credential(&c),
        &PluginSecret::new(
            format!("{} {token}", provider.authorization_scheme),
            vec![provider.api_origin.to_string()],
            now(),
        ),
    )?;
    // Preserve refresh credentials host-side; access failures currently request reauthorization.
    if let Some(refresh) = data
        .pointer(&provider.refresh_token_pointer)
        .and_then(Value::as_str)
    {
        let mut k = credential(&c);
        k.name = format!("{}-refresh", provider.id);
        app.store.set_plugin_secret(
            &k,
            &PluginSecret::new(refresh.into(), vec![provider.api_origin.to_string()], now()),
        )?;
    }
    put(&app.store, "connection", &c.id, &c)?;
    Ok(HttpResponse::Ok().json(c))
}
/// Fixed script, no interpolation of provider-controlled values into executable HTML.
pub async fn callback(provider_id: web::Path<String>) -> Result<HttpResponse> {
    let provider = provider::load(&provider_id)?;
    let target = serde_json::to_string(&provider.config()?.frontend_origin)
        .map_err(|e| e.to_string())?
        .replace("<", "\\u003c");
    let event = serde_json::to_string(&provider.callback_event)
        .map_err(|e| e.to_string())?
        .replace("<", "\\u003c");
    Ok(HttpResponse::Ok().insert_header(("Cache-Control","no-store")).insert_header(("Referrer-Policy","no-referrer")).insert_header(("Content-Security-Policy","default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'" )).content_type("text/html; charset=utf-8").body(r#"<!doctype html><title>Provider connection</title><p>Return to Atomic to finish connecting. You can close this window.</p><script>const p=new URLSearchParams(location.search); if(window.opener){window.opener.postMessage({type:EVENT,provider:PROVIDER,state:p.get('state'),code:p.get('code'),error:p.get('error')},TARGET_ORIGIN);} history.replaceState(null,'',location.pathname);</script>"#.replace("TARGET_ORIGIN", &target).replace("PROVIDER",&serde_json::to_string(&provider.id).map_err(|e|e.to_string())?).replace("EVENT",&event)))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Discover {
    drive: String,
    connection: String,
    #[serde(default)]
    query: String,
    cursor: Option<String>,
}
fn choices(provider: &Provider, data: &Value) -> Value {
    let d = &provider.discovery;
    let results:Vec<Value>=data.pointer(&d.results_pointer).and_then(Value::as_array).into_iter().flatten()
        .filter(|v|v.pointer(&d.include_pointer)==Some(&d.include_value))
        .filter_map(|v|{
            let id=v.pointer(&d.id_pointer)?.as_str()?;
            let name=v.pointer(&d.title_pointer).and_then(Value::as_array).into_iter().flatten()
                .filter_map(|part|d.text_pointers.iter().find_map(|p|part.pointer(p).and_then(Value::as_str))).collect::<String>();
            Some(json!({"id":id,"name":name,"icon":v.pointer(&d.icon_pointer).and_then(Value::as_str).unwrap_or(&d.default_icon)}))
        }).collect();
    json!({"results":results,"cursor":data.pointer(&d.cursor_pointer)})
}
pub async fn discover(
    provider_id: web::Path<String>,
    app: web::Data<AppState>,
    body: web::Json<Discover>,
    req: actix_web::HttpRequest,
    ctx: RequestContext,
) -> Result<HttpResponse> {
    let provider = provider::load(&provider_id)?;
    let a = actor(&app, &req, &ctx, &body.drive).await?;
    let c: Connection = get(&app.store, "connection", &body.connection)?;
    owned(&c, &provider.id, &body.drive, &a)?;
    if body.query.len() > 256 || body.cursor.as_ref().is_some_and(|s| s.len() > 1024) {
        return Err("Search is too long".into());
    }
    let mut payload = provider.discovery.body.clone();
    provider::set_pointer(
        &mut payload,
        &provider.discovery.query_pointer,
        json!(body.query),
    )?;
    if let Some(cursor) = &body.cursor {
        provider::set_pointer(
            &mut payload,
            &provider.discovery.cursor_request_pointer,
            json!(cursor),
        )?;
    }
    let method = reqwest::Method::from_bytes(provider.discovery.method.as_bytes())
        .map_err(|_| "Invalid provider discovery method")?;
    let request = authorized_request(&app.store, &c, &provider, method)?;
    let request = request.json(&payload);
    let r = request
        .send()
        .await
        .map_err(|_| "Cannot reach provider. Try again.")?;
    let data = response_json(r, &provider.label).await?;
    Ok(HttpResponse::Ok().json(choices(&provider, &data)))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bind {
    drive: String,
    connection: String,
    plugin: String,
}
pub async fn bind(
    provider_id: web::Path<String>,
    app: web::Data<AppState>,
    body: web::Json<Bind>,
    req: actix_web::HttpRequest,
    ctx: RequestContext,
) -> Result<HttpResponse> {
    let provider = provider::load(&provider_id)?;
    let a = super::plugin_schedule::authorize(&app, &req, &ctx, &body.plugin).await?;
    let host = StoreHost {
        db: std::sync::Arc::new(app.store.clone()),
        drive: body.drive.clone(),
        plugin: body.plugin.clone(),
        for_agent: a.clone(),
        manifest: None,
    };
    host.validate_binding().await?;
    let c: Connection = get(&app.store, "connection", &body.connection)?;
    owned(&c, &provider.id, &body.drive, &a.to_string())?;
    let mut alias = PluginSecret::new(String::new(), vec![provider.api_origin.to_string()], now());
    alias.connection = Some(credential(&c));
    app.store.set_plugin_secret(
        &PluginSecretKey::new(&body.drive, &body.plugin, &provider.id),
        &alias,
    )?;
    app.store.flush()?;
    Ok(HttpResponse::Ok().json(true))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn consumed_login_cannot_be_loaded_again() {
        let db = Db::init_temp("oauth_state_consumption").await.unwrap();
        let id = random_id();
        put(
            &db,
            "pending",
            &id,
            &Pending {
                service: None,
                drive: "drive".into(),
                actor: "alice".into(),
                expires: now() + TTL,
                connection: None,
                provider: "notion".into(),
            },
        )
        .unwrap();
        let p: Pending = get(&db, "pending", &id).unwrap();
        assert!(validate_pending(&p, "drive", "bob", now()).is_err());
        assert!(get::<Pending>(&db, "pending", &id).is_ok());
        validate_pending(&p, "drive", "alice", now()).unwrap();
        remove(&db, "pending", &id).unwrap();
        assert!(get::<Pending>(&db, "pending", &id).is_err());
    }
    #[test]
    fn connections_are_not_shared_across_actors_or_drives() {
        let c = Connection {
            id: "id".into(),
            provider: "notion".into(),
            drive: "drive".into(),
            actor: "alice".into(),
            account: "provider-account".into(),
            name: "Work".into(),
        };
        assert!(owned(&c, "notion", "drive", "alice").is_ok());
        assert!(owned(&c, "notion", "drive", "bob").is_err());
        assert!(owned(&c, "notion", "other", "alice").is_err());
        assert!(owned(&c, "other", "drive", "alice").is_err());
        let view = serde_json::to_value(&c).unwrap();
        assert!(view.get("access_token").is_none());
    }
    #[test]
    fn oauth_pending_is_actor_drive_and_time_bound() {
        let p = Pending {
            service: None,
            actor: "alice".into(),
            drive: "drive".into(),
            expires: 100,
            connection: None,
            provider: "notion".into(),
        };
        assert!(validate_pending(&p, "drive", "alice", 99).is_ok());
        assert!(validate_pending(&p, "drive", "bob", 99).is_err());
        assert!(validate_pending(&p, "other", "alice", 99).is_err());
        assert!(validate_pending(&p, "drive", "alice", 100).is_err());
    }
    #[test]
    fn picker_returns_names_and_emoji_without_provider_payload() {
        let result = choices(
            &provider::load("notion").unwrap(),
            &json!({"results":[{"object":"data_source","id":"abc","title":[{"plain_text":"Tasks"}],"icon":{"emoji":"✅"},"private":"omit"},{"object":"page","id":"no"}],"next_cursor":"next"}),
        );
        assert_eq!(
            result,
            json!({"results":[{"id":"abc","name":"Tasks","icon":"✅"}],"cursor":"next"})
        );
    }
}
