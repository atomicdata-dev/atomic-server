//! Notion authorization adapter shared by local and managed deployments.
use crate::errors::{AtomicServerError, AtomicServerResult as Result};
use serde_json::{json, Value};

pub(crate) async fn exchange_code(
    client_id: &str,
    secret: &str,
    callback: &str,
    code: &str,
) -> Result<Value> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "Could not initialize Notion authorization")?;
    let response = client
        .post("https://api.notion.com/v1/oauth/token")
        .basic_auth(client_id, Some(secret))
        .json(&json!({"grant_type":"authorization_code","code":code,"redirect_uri":callback}))
        .send()
        .await
        .map_err(|_| "Could not finish Notion sign-in. Connect again.")?;
    response_json(response).await
}

pub(crate) async fn response_json(mut r: reqwest::Response) -> Result<Value> {
    let status = r.status();
    if !status.is_success() {
        return Err(AtomicServerError::bad_request(match status.as_u16() {
            401 => "Notion access has expired or was revoked. Reconnect Notion to continue.",
            403 | 404 => {
                "Notion cannot access this database. Share it with the connection, then try again."
            }
            429 => "Notion is busy. Wait a moment and try again.",
            _ => "Notion could not complete the request. Try again.",
        }));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = r
        .chunk()
        .await
        .map_err(|_| "Notion response interrupted. Try again.")?
    {
        if bytes.len() + chunk.len() > 2_000_000 {
            return Err("Notion response too large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "Notion returned an invalid response".into())
}
