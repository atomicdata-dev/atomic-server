//! Provider-independent OAuth token exchange and bounded JSON responses.
use super::provider::{Provider, TokenAuth, TokenEncoding};
use crate::errors::{AtomicServerError, AtomicServerResult as Result};
use serde_json::{Map, Value};

pub(crate) async fn exchange_code(
    provider: &Provider,
    client_id: &str,
    secret: &str,
    callback: &str,
    code: &str,
) -> Result<Value> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "Could not initialize authorization")?;
    let mut body = Map::from_iter([
        (
            "grant_type".into(),
            Value::String("authorization_code".into()),
        ),
        ("code".into(), Value::String(code.into())),
        ("redirect_uri".into(), Value::String(callback.into())),
    ]);
    let mut request = client.post(provider.token_url.clone());
    match provider.token_auth {
        TokenAuth::Basic => request = request.basic_auth(client_id, Some(secret)),
        TokenAuth::Body => {
            body.insert("client_id".into(), Value::String(client_id.into()));
            body.insert("client_secret".into(), Value::String(secret.into()));
        }
    }
    request = match provider.token_encoding {
        TokenEncoding::Json => request.json(&body),
        TokenEncoding::Form => {
            let encoded = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(body.iter().map(|(key, value)| {
                    (
                        key.as_str(),
                        value.as_str().expect("OAuth body values are strings"),
                    )
                }))
                .finish();
            request
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(encoded)
        }
    };
    response_json(
        request
            .send()
            .await
            .map_err(|_| "Could not finish sign-in. Connect again.")?,
        &provider.label,
    )
    .await
}

pub(crate) async fn response_json(mut response: reqwest::Response, label: &str) -> Result<Value> {
    let status = response.status();
    if !status.is_success() {
        return Err(AtomicServerError::bad_request(format!(
            "{label} returned HTTP {}; reconnect or check the selected account",
            status.as_u16()
        )));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Provider response interrupted")?
    {
        if bytes.len() + chunk.len() > 2_000_000 {
            return Err("Provider response too large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "Provider returned an invalid response".into())
}
