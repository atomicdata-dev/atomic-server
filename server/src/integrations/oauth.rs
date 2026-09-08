use super::catalog::OAuth;
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde::Deserialize;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use syncables::client::client::{Fetch, HttpRequest, HttpResponse};
use tokio::sync::Mutex;

pub fn nonce() -> String {
    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn authorization_url(
    oauth: &OAuth,
    client_id: &str,
    redirect: &str,
    state: &str,
    verifier: &str,
) -> Result<String> {
    let mut url = url::Url::parse(&oauth.authorization_url)?;
    let challenge = URL_SAFE_NO_PAD.encode(ring::digest::digest(
        &ring::digest::SHA256,
        verifier.as_bytes(),
    ));
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in &oauth.params {
            query.append_pair(key, value);
        }
        query.extend_pairs([
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", redirect),
            ("state", state),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            (
                "scope",
                &oauth.scopes.keys().cloned().collect::<Vec<_>>().join(" "),
            ),
        ]);
    }
    Ok(url.into())
}

// Intentionally no Debug/Serialize: provider tokens never enter logs or UI data.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
}
struct Tokens {
    access: String,
    refresh: Option<String>,
    expires: Option<Instant>,
}

pub struct OAuthFetch {
    oauth: OAuth,
    client_id: String,
    client_secret: String,
    tokens: Mutex<Tokens>,
    http: reqwest::Client,
    fetch: reflector_rs::ReqwestFetch,
}

impl OAuthFetch {
    pub async fn exchange(
        oauth: OAuth,
        client_id: String,
        client_secret: String,
        redirect: &str,
        code: &str,
        verifier: &str,
    ) -> Result<Arc<Self>> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()?;
        let token = request_token(
            &http,
            &oauth.token_url,
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &client_id),
                ("client_secret", &client_secret),
                ("redirect_uri", redirect),
                ("code", code),
                ("code_verifier", verifier),
            ],
        )
        .await?;
        Ok(Arc::new(Self {
            oauth,
            client_id,
            client_secret,
            http,
            fetch: reflector_rs::ReqwestFetch::new(),
            tokens: Mutex::new(Tokens {
                access: token.access_token,
                refresh: token.refresh_token,
                expires: token
                    .expires_in
                    .map(|s| Instant::now() + Duration::from_secs(s.min(31536000))),
            }),
        }))
    }

    async fn token(&self, rejected: Option<&str>) -> Result<String> {
        let mut tokens = self.tokens.lock().await;
        let expired = tokens
            .expires
            .is_some_and(|at| at <= Instant::now() + Duration::from_secs(30));
        if expired || rejected.is_some_and(|old| old == tokens.access) {
            let refresh = tokens
                .refresh
                .as_deref()
                .context("Authorization expired. Connect the integration again.")?;
            let token = request_token(
                &self.http,
                &self.oauth.token_url,
                &[
                    ("grant_type", "refresh_token"),
                    ("client_id", &self.client_id),
                    ("client_secret", &self.client_secret),
                    ("refresh_token", refresh),
                ],
            )
            .await?;
            tokens.access = token.access_token;
            if let Some(refresh) = token.refresh_token {
                tokens.refresh = Some(refresh);
            }
            tokens.expires = token
                .expires_in
                .map(|s| Instant::now() + Duration::from_secs(s.min(31536000)));
        }
        Ok(tokens.access.clone())
    }
}

async fn request_token(
    http: &reqwest::Client,
    url: &str,
    form: &[(&str, &str)],
) -> Result<TokenResponse> {
    let response = http
        .post(url)
        .header("Accept", "application/json")
        .form(form)
        .send()
        .await
        .context("OAuth token endpoint unavailable")?;
    ensure!(
        response.status().is_success(),
        "OAuth token exchange failed (HTTP {})",
        response.status()
    );
    let token: TokenResponse = response
        .json()
        .await
        .context("OAuth provider did not return an access token")?;
    ensure!(
        !token.access_token.is_empty(),
        "OAuth provider returned an empty access token"
    );
    Ok(token)
}

#[async_trait::async_trait]
impl Fetch for OAuthFetch {
    async fn fetch(&self, mut request: HttpRequest) -> syncables::Result<HttpResponse> {
        let token = self
            .token(None)
            .await
            .map_err(|e| syncables::Error::Http(e.to_string()))?;
        request
            .headers
            .insert("Authorization".into(), format!("Bearer {token}"));
        let response =
            fetch_with_timeout(&self.fetch, request.clone(), Duration::from_secs(60)).await?;
        if response.status != 401 {
            return Ok(response);
        }
        let token = self
            .token(Some(&token))
            .await
            .map_err(|e| syncables::Error::Http(e.to_string()))?;
        request
            .headers
            .insert("Authorization".into(), format!("Bearer {token}"));
        fetch_with_timeout(&self.fetch, request, Duration::from_secs(60)).await
    }
}

// A stalled provider must not leave the whole import waiting on an unbounded
// reqwest request. Includes reading the response body, not only connecting.
async fn fetch_with_timeout(
    fetch: &impl Fetch,
    request: HttpRequest,
    timeout: Duration,
) -> syncables::Result<HttpResponse> {
    tokio::time::timeout(timeout, fetch.fetch(request))
        .await
        .map_err(|_| syncables::Error::Http("Provider request timed out".into()))?
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StalledProvider;
    #[async_trait::async_trait]
    impl Fetch for StalledProvider {
        async fn fetch(&self, _: HttpRequest) -> syncables::Result<HttpResponse> {
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn stalled_provider_returns_an_error() {
        let request = HttpRequest {
            method: "GET".into(),
            url: "https://example.com/events".into(),
            headers: Default::default(),
            body: None,
        };
        let error = fetch_with_timeout(&StalledProvider, request, Duration::from_millis(10))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Provider request timed out"));
    }
}
