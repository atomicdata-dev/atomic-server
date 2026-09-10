//! Outbound host client. These requests never originate in the browser.
use super::service::{base_url, Attempt, Redemption};
use crate::errors::{AtomicServerError, AtomicServerResult as Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Clone)]
pub(crate) struct Remote {
    pub origin: String,
    token: String,
}
#[derive(Serialize, Deserialize)]
pub(crate) struct Ticket {
    pub id: String,
    pub proof: String,
    pub url: String,
}
impl Remote {
    pub(crate) fn new(origin: &str, token: String) -> Result<Self> {
        if token.len() < 32 || token.len() > 1024 {
            return Err("Invalid authorization service credential".into());
        }
        Ok(Self {
            origin: base_url(origin)?,
            token,
        })
    }
    pub fn from_env() -> Result<Option<Self>> {
        let Ok(origin) = std::env::var("ATOMIC_OAUTH_SERVICE_URL") else {
            return Ok(None);
        };
        let token = std::env::var("ATOMIC_OAUTH_SERVICE_TOKEN")
            .map_err(|_| "Missing authorization service credential")?;
        if token.len() < 32 || token.len() > 1024 {
            return Err("Invalid authorization service credential".into());
        }
        Ok(Some(Self::new(&origin, token)?))
    }
    async fn post<T: Serialize>(&self, path: &str, body: &T) -> Result<Value> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| "Could not initialize authorization client")?;
        let mut response = client
            .post(format!("{}/oauth-service/notion/{path}", self.origin))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
            .map_err(|_| "Cannot reach authorization service. Try again.")?;
        if !response.status().is_success() {
            return Err(AtomicServerError::bad_request("Authorization service refused the request. Reconnect or ask your server administrator to check its configuration."));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "Authorization service response interrupted")?
        {
            if bytes.len() + chunk.len() > 65536 {
                return Err("Authorization service response too large".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| "Invalid authorization service response".into())
    }
    pub async fn start(&self, actor: String, drive: String, attempt: String) -> Result<Ticket> {
        let value = self
            .post(
                "start",
                &Attempt {
                    actor,
                    drive,
                    attempt,
                },
            )
            .await?;
        let ticket: Ticket =
            serde_json::from_value(value).map_err(|_| "Invalid authorization ticket")?;
        if ticket.id.len() != 64 || ticket.proof.len() != 64 {
            return Err("Invalid authorization ticket".into());
        }
        let u = url::Url::parse(&ticket.url).map_err(|_| "Invalid authorization URL")?;
        if u.origin().ascii_serialization() != "https://api.notion.com"
            || u.path() != "/v1/oauth/authorize"
            || !u.username().is_empty()
            || u.password().is_some()
        {
            return Err("Invalid Notion authorization URL".into());
        }
        let query: std::collections::BTreeMap<_, _> = u.query_pairs().into_owned().collect();
        if query.get("state") != Some(&ticket.id)
            || query.get("redirect_uri")
                != Some(&format!("{}/oauth-service/notion/callback", self.origin))
            || query.get("response_type").map(String::as_str) != Some("code")
        {
            return Err("Authorization ticket URL does not match this service".into());
        }
        Ok(ticket)
    }
    pub async fn redeem(
        &self,
        ticket: &Ticket,
        actor: String,
        drive: String,
        attempt: String,
    ) -> Result<Value> {
        self.post(
            "redeem",
            &Redemption {
                id: ticket.id.clone(),
                proof: ticket.proof.clone(),
                binding: Attempt {
                    actor,
                    drive,
                    attempt,
                },
            },
        )
        .await
    }
}
