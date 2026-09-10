//! Optional shared authorization HTTP service. Only provisioned AtomicServers
//! may create/redeem attempts; the provider callback uses random single-use state.
use super::{handoff, notion};
use crate::errors::{AtomicServerError, AtomicServerResult as Result};
use actix_web::{web, HttpRequest, HttpResponse};
use atomic_lib::{db::trees::Tree, Db};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Arc};
#[derive(Clone)]
pub struct AuthorizationService {
    db: Db,
    clients: BTreeMap<String, String>,
    public_url: String,
    client_id: String,
    client_secret: String,
}
fn now() -> i64 {
    atomic_lib::utils::now()
}
fn denied() -> AtomicServerError {
    AtomicServerError {
        message: "Authorization service authentication failed".into(),
        error_type: crate::errors::AppErrorType::Unauthorized,
        error_resource: None,
    }
}
/// Public base URLs never include credentials, query strings or redirect targets.
pub(crate) fn base_url(value: &str) -> Result<String> {
    let u = url::Url::parse(value).map_err(|_| "Invalid authorization service URL")?;
    if !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || u.path() != "/"
        || (u.scheme() != "https"
            && !(u.scheme() == "http" && matches!(u.host_str(), Some("localhost" | "127.0.0.1"))))
    {
        return Err(
            "Authorization service URL must be an HTTPS origin (HTTP is allowed only on loopback)"
                .into(),
        );
    }
    Ok(u.origin().ascii_serialization())
}
impl AuthorizationService {
    pub fn from_env(db: Db) -> Result<Option<Arc<Self>>> {
        let Ok(public) = std::env::var("ATOMIC_OAUTH_PUBLIC_URL") else {
            return Ok(None);
        };
        let env = |key| {
            std::env::var(key).map_err(|_| {
                AtomicServerError::bad_request("Authorization service configuration is incomplete")
            })
        };
        let clients: BTreeMap<String, String> = serde_json::from_str(&env("ATOMIC_OAUTH_CLIENTS")?)
            .map_err(|_| "Invalid authorization service client configuration")?;
        if clients.is_empty()
            || clients.len() > 10000
            || clients.iter().any(|(id, token)| {
                id.is_empty() || id.len() > 128 || token.len() < 32 || token.len() > 1024
            })
        {
            return Err(
                "Authorization service clients need unique IDs and strong per-server tokens".into(),
            );
        }
        let client_id = env("ATOMIC_NOTION_CLIENT_ID")?;
        let client_secret = env("ATOMIC_NOTION_CLIENT_SECRET")?;
        if client_id.is_empty() || client_secret.is_empty() {
            return Err("Notion OAuth credentials are empty".into());
        }
        Ok(Some(Arc::new(Self {
            db,
            clients,
            public_url: base_url(&public)?,
            client_id,
            client_secret,
        })))
    }
    fn authenticate(&self, req: &HttpRequest) -> Result<String> {
        let token = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .filter(|s| s.len() >= 32 && s.len() <= 1024)
            .ok_or_else(denied)?;
        let hash = blake3::hash(token.as_bytes());
        self.clients
            .iter()
            .find(|(_, expected)| blake3::hash(expected.as_bytes()) == hash)
            .map(|(id, _)| id.clone())
            .ok_or_else(denied)
    }
    async fn admission(&self, server: &str) -> Result<()> {
        let key = format!("oauth-admission/v1/{server}");
        let _lock = self.db.lock_plugin(&key).await;
        let mut starts: Vec<i64> = self
            .db
            .kv
            .get(Tree::PluginMeta, key.as_bytes())?
            .map(|b| serde_json::from_slice(&b))
            .transpose()
            .map_err(|_| "Invalid authorization admission state")?
            .unwrap_or_default();
        let at = now();
        starts.retain(|v| *v > at - 60_000);
        if starts.len() >= 10 {
            return Err(AtomicServerError::bad_request(
                "Too many sign-in attempts. Wait a minute and try again.",
            ));
        }
        starts.push(at);
        self.db.kv.insert(
            Tree::PluginMeta,
            key.as_bytes(),
            &serde_json::to_vec(&starts).map_err(|e| e.to_string())?,
        )?;
        self.db.flush()?;
        Ok(())
    }
    pub fn spawn_cleanup(self: &Arc<Self>) {
        let service = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut cursor = None;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let Some(s) = service.upgrade() else { break };
                match handoff::cleanup(&s.db, now(), 1000, cursor.as_deref()).await {
                    Ok(page) => cursor = page.next,
                    Err(_) => {
                        cursor = None;
                        tracing::warn!("Authorization handoff cleanup failed");
                    }
                }
            }
        });
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Attempt {
    pub actor: String,
    pub drive: String,
    pub attempt: String,
}
fn binding(server: String, b: &Attempt) -> handoff::Binding {
    handoff::Binding {
        server,
        actor: b.actor.clone(),
        drive: b.drive.clone(),
        attempt: b.attempt.clone(),
        provider: "notion".into(),
    }
}
fn private_json(v: Value) -> HttpResponse {
    HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-store"))
        .json(v)
}
async fn start(
    s: web::Data<AuthorizationService>,
    req: HttpRequest,
    body: web::Json<Attempt>,
) -> Result<HttpResponse> {
    let server = s.authenticate(&req)?;
    s.admission(&server).await?;
    let ticket = handoff::begin(&s.db, binding(server, &body), now())?;
    let callback = format!("{}/oauth-service/notion/callback", s.public_url);
    let mut url = url::Url::parse("https://api.notion.com/v1/oauth/authorize").unwrap();
    url.query_pairs_mut().extend_pairs([
        ("owner", "user"),
        ("response_type", "code"),
        ("client_id", s.client_id.as_str()),
        ("redirect_uri", callback.as_str()),
        ("state", ticket.id.as_str()),
    ]);
    // This endpoint is server-to-server only; the local host must strip proof.
    Ok(private_json(
        json!({"id":ticket.id,"proof":ticket.proof,"url":url.as_str()}),
    ))
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Redemption {
    pub id: String,
    pub proof: String,
    pub binding: Attempt,
}
async fn redeem(
    s: web::Data<AuthorizationService>,
    req: HttpRequest,
    body: web::Json<Redemption>,
) -> Result<HttpResponse> {
    let server = s.authenticate(&req)?;
    let result = handoff::redeem(
        &s.db,
        &body.id,
        &body.proof,
        &binding(server, &body.binding),
        now(),
    )
    .await?;
    let value = match result {
        None => json!({"pending":true}),
        Some(payload) => {
            serde_json::from_str(&payload).map_err(|_| "Invalid authorization result")?
        }
    };
    Ok(private_json(value))
}
#[derive(Deserialize)]
struct Callback {
    state: String,
    code: Option<String>,
    error: Option<String>,
}
async fn callback(
    s: web::Data<AuthorizationService>,
    query: web::Query<Callback>,
) -> Result<HttpResponse> {
    let binding = handoff::claim_callback(&s.db, &query.state, now()).await?;
    let payload = if query.error.is_some() {
        json!({"error":"Notion sign-in was cancelled. You can try again."})
    } else if let Some(code) = query
        .code
        .as_ref()
        .filter(|s| !s.is_empty() && s.len() < 4096)
    {
        let callback = format!("{}/oauth-service/notion/callback", s.public_url);
        match notion::exchange_code(&s.client_id, &s.client_secret, &callback, code).await {
            Ok(data) => json!({"credentials":data}),
            Err(_) => json!({"error":"Could not finish Notion sign-in. Connect again."}),
        }
    } else {
        json!({"error":"Notion did not return an authorization code. Connect again."})
    };
    handoff::complete(&s.db, &query.state, &binding, &payload.to_string(), now()).await?;
    Ok(HttpResponse::Ok().insert_header(("Cache-Control","no-store")).insert_header(("Referrer-Policy","no-referrer")).insert_header(("Content-Security-Policy","default-src 'none'; frame-ancestors 'none'" )).content_type("text/html; charset=utf-8").body("<!doctype html><title>Return to Atomic</title><p>Authorization finished. Return to Atomic to continue.</p>"))
}
pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/oauth-service/notion")
            .app_data(web::JsonConfig::default().limit(8192))
            .route("/start", web::post().to(start))
            .route("/redeem", web::post().to(redeem))
            .route("/callback", web::get().to(callback)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};
    const TOKEN_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TOKEN_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    async fn fixture(name: &str) -> AuthorizationService {
        let db = Db::init_temp(name).await.unwrap();
        db.set_node_key([8; 32]);
        AuthorizationService {
            db,
            clients: BTreeMap::from([
                ("host-a".into(), TOKEN_A.into()),
                ("host-b".into(), TOKEN_B.into()),
            ]),
            public_url: "http://localhost:1234".into(),
            client_id: "fixture-client".into(),
            client_secret: "fixture-secret".into(),
        }
    }
    #[actix_web::test]
    async fn http_handoff_authenticates_server_and_rejects_replay() {
        let s = fixture("oauth_http_handoff").await;
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(s.clone()))
                .configure(routes),
        )
        .await;
        let body = json!({"actor":"alice","drive":"drive","attempt":"attempt"});
        let anonymous = test::TestRequest::post()
            .uri("/oauth-service/notion/start")
            .set_json(&body)
            .to_request();
        assert_eq!(test::call_service(&app, anonymous).await.status(), 401);
        let forged = test::TestRequest::post()
            .uri("/oauth-service/notion/start")
            .insert_header(("Authorization", format!("Bearer {TOKEN_A}")))
            .set_json(
                json!({"server":"host-b","actor":"alice","drive":"drive","attempt":"attempt"}),
            )
            .to_request();
        assert_eq!(test::call_service(&app, forged).await.status(), 400);
        let request = test::TestRequest::post()
            .uri("/oauth-service/notion/start")
            .insert_header(("Authorization", format!("Bearer {TOKEN_A}")))
            .set_json(&body)
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.headers().get("Cache-Control").unwrap(), "no-store");
        let ticket: Value = test::read_body_json(response).await;
        assert!(!ticket["url"]
            .as_str()
            .unwrap()
            .contains(ticket["proof"].as_str().unwrap()));
        let b = handoff::Binding {
            server: "host-a".into(),
            actor: "alice".into(),
            drive: "drive".into(),
            provider: "notion".into(),
            attempt: "attempt".into(),
        };
        handoff::complete(
            &s.db,
            ticket["id"].as_str().unwrap(),
            &b,
            r#"{"credentials":{"access_token":"host-only"}}"#,
            now(),
        )
        .await
        .unwrap();
        let redemption = json!({"id":ticket["id"],"proof":ticket["proof"],"binding":body});
        let wrong = test::TestRequest::post()
            .uri("/oauth-service/notion/redeem")
            .insert_header(("Authorization", format!("Bearer {TOKEN_B}")))
            .set_json(&redemption)
            .to_request();
        assert!(!test::call_service(&app, wrong).await.status().is_success());
        let right = || {
            test::TestRequest::post()
                .uri("/oauth-service/notion/redeem")
                .insert_header(("Authorization", format!("Bearer {TOKEN_A}")))
                .set_json(&redemption)
                .to_request()
        };
        let response = test::call_service(&app, right()).await;
        assert!(response.status().is_success());
        assert_eq!(
            test::read_body_json::<Value, _>(response).await["credentials"]["access_token"],
            "host-only"
        );
        assert!(!test::call_service(&app, right())
            .await
            .status()
            .is_success());
    }
    #[actix_web::test]
    async fn callback_cancellation_is_single_use_and_never_returns_proof() {
        let s = fixture("oauth_http_cancel").await;
        let b = handoff::Binding {
            server: "host-a".into(),
            actor: "alice".into(),
            drive: "drive".into(),
            provider: "notion".into(),
            attempt: "attempt".into(),
        };
        let t = handoff::begin(&s.db, b.clone(), now()).unwrap();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(s.clone()))
                .configure(routes),
        )
        .await;
        let request = || {
            test::TestRequest::get()
                .uri(&format!(
                    "/oauth-service/notion/callback?state={}&error=access_denied",
                    t.id
                ))
                .to_request()
        };
        let response = test::call_service(&app, request()).await;
        assert!(response.status().is_success());
        let html = String::from_utf8(test::read_body(response).await.to_vec()).unwrap();
        assert!(!html.contains(&t.proof));
        assert!(!html.contains("access_token"));
        assert!(!test::call_service(&app, request())
            .await
            .status()
            .is_success());
        let result = handoff::redeem(&s.db, &t.id, &t.proof, &b, now())
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains("cancelled"));
    }
    #[actix_web::test]
    async fn admission_is_bounded_per_authenticated_server() {
        let s = fixture("oauth_http_admission").await;
        for _ in 0..10 {
            s.admission("host-a").await.unwrap();
        }
        assert!(s.admission("host-a").await.is_err());
        assert!(s.admission("host-b").await.is_ok());
    }
    #[actix_web::test]
    async fn outbound_client_retrieves_over_real_http_without_inbound_host_callback() {
        let mut service = fixture("oauth_real_http").await;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        service.public_url = origin.clone();
        let data = web::Data::new(service.clone());
        let server =
            actix_web::HttpServer::new(move || App::new().app_data(data.clone()).configure(routes))
                .listen(listener)
                .unwrap()
                .run();
        let handle = server.handle();
        actix_web::rt::spawn(server);
        let client = crate::oauth::remote::Remote::new(&origin, TOKEN_A.into()).unwrap();
        let ticket = client
            .start("alice".into(), "drive".into(), "attempt".into())
            .await
            .unwrap();
        let pending = client
            .redeem(&ticket, "alice".into(), "drive".into(), "attempt".into())
            .await
            .unwrap();
        assert_eq!(pending, json!({"pending":true}));
        let b = handoff::Binding {
            server: "host-a".into(),
            actor: "alice".into(),
            drive: "drive".into(),
            provider: "notion".into(),
            attempt: "attempt".into(),
        };
        handoff::complete(
            &service.db,
            &ticket.id,
            &b,
            r#"{"credentials":{"access_token":"host-only","workspace_id":"workspace"}}"#,
            now(),
        )
        .await
        .unwrap();
        let result = client
            .redeem(&ticket, "alice".into(), "drive".into(), "attempt".into())
            .await
            .unwrap();
        assert_eq!(result["credentials"]["access_token"], "host-only");
        assert!(client
            .redeem(&ticket, "alice".into(), "drive".into(), "attempt".into())
            .await
            .is_err());
        handle.stop(true).await;
    }
    #[actix_web::test]
    async fn service_urls_refuse_redirects_credentials_and_remote_plaintext() {
        for url in [
            "http://example.com",
            "https://user:secret@example.com",
            "https://example.com/path",
            "https://example.com?token=x",
            "https://example.com#fragment",
        ] {
            assert!(base_url(url).is_err());
        }
        assert_eq!(
            base_url("http://localhost:9883/").unwrap(),
            "http://localhost:9883"
        );
        assert_eq!(
            base_url("https://auth.example.com").unwrap(),
            "https://auth.example.com"
        );
    }
}
