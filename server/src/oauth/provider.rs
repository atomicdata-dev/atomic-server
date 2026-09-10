//! Validated OAuth/provider descriptors generated from Devonian platform lenses.
//!
//! The checked-in artifact is immutable at runtime. Request data selects an id;
//! it can never supply an endpoint, header, OAuth parameter, or response mapping.
use crate::errors::{AtomicServerError, AtomicServerResult as Result};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use url::Url;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    source: String,
    revision: String,
    providers: Vec<Record>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    id: String,
    label: String,
    callback_event: String,
    api_origin: String,
    authorization_url: String,
    token_url: String,
    #[serde(default)]
    authorization_params: BTreeMap<String, String>,
    #[serde(default)]
    api_headers: BTreeMap<String, String>,
    token_auth: TokenAuth,
    token_encoding: TokenEncoding,
    authorization_scheme: String,
    access_token_pointer: String,
    refresh_token_pointer: String,
    account: Account,
    discovery: Discovery,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TokenAuth {
    Basic,
    Body,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TokenEncoding {
    Json,
    Form,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Account {
    id_pointer: String,
    name_pointer: String,
    default_name: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Discovery {
    pub path: String,
    pub method: String,
    pub body: Value,
    pub results_pointer: String,
    pub cursor_pointer: String,
    pub include_pointer: String,
    pub include_value: Value,
    pub id_pointer: String,
    pub title_pointer: String,
    pub text_pointers: Vec<String>,
    pub icon_pointer: String,
    pub default_icon: String,
    pub query_pointer: String,
    pub cursor_request_pointer: String,
}
#[derive(Clone)]
pub(crate) struct Provider {
    pub id: String,
    pub label: String,
    pub callback_event: String,
    pub api_origin: Url,
    pub authorization_url: Url,
    pub token_url: Url,
    pub authorization_params: BTreeMap<String, String>,
    pub api_headers: BTreeMap<String, String>,
    pub token_auth: TokenAuth,
    pub token_encoding: TokenEncoding,
    pub authorization_scheme: String,
    pub access_token_pointer: String,
    pub refresh_token_pointer: String,
    account: Account,
    pub discovery: Discovery,
}
pub(crate) struct Config {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub frontend_origin: String,
}
pub(crate) fn registered_ids() -> Result<Vec<String>> {
    let catalog: Catalog = serde_json::from_str(include_str!("providers.json"))
        .map_err(|_| "Invalid vendored OAuth provider metadata")?;
    Ok(catalog.providers.into_iter().map(|r| r.id).collect())
}
pub(crate) fn load(id: &str) -> Result<Provider> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("Invalid OAuth provider id".into());
    }
    let catalog: Catalog = serde_json::from_str(include_str!("providers.json"))
        .map_err(|_| "Invalid vendored OAuth provider metadata")?;
    if catalog.source != "https://github.com/localthought/devonian"
        || catalog.revision.len() != 40
        || !catalog.revision.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("OAuth provider metadata has invalid provenance".into());
    }
    let r = catalog
        .providers
        .into_iter()
        .find(|r| r.id == id)
        .ok_or("OAuth provider is not registered")?;
    let api_origin = origin(&r.api_origin)?;
    let authorization_url = endpoint(&r.authorization_url)?;
    let token_url = endpoint(&r.token_url)?;
    validate_path(&r.discovery.path)?;
    if r.discovery.method != "POST"
        || !r.account.id_pointer.starts_with('/')
        || !r.account.name_pointer.starts_with('/')
        || r.api_headers.iter().any(|(k, v)| {
            k.is_empty()
                || k.eq_ignore_ascii_case("authorization")
                || k.contains(['\r', '\n'])
                || v.contains(['\r', '\n'])
        })
        || r.authorization_params.keys().any(|k| {
            matches!(
                k.as_str(),
                "client_id" | "redirect_uri" | "state" | "response_type"
            )
        })
        || r.authorization_scheme.is_empty()
        || r.authorization_scheme.contains(char::is_whitespace)
        || !r.access_token_pointer.starts_with('/')
        || !r.refresh_token_pointer.starts_with('/')
    {
        return Err("Invalid OAuth provider metadata".into());
    }
    if r.callback_event.is_empty() || r.callback_event.len() > 128 {
        return Err("Invalid OAuth callback event".into());
    }
    Ok(Provider {
        id: r.id,
        label: r.label,
        callback_event: r.callback_event,
        api_origin,
        authorization_url,
        token_url,
        authorization_params: r.authorization_params,
        api_headers: r.api_headers,
        token_auth: r.token_auth,
        token_encoding: r.token_encoding,
        authorization_scheme: r.authorization_scheme,
        access_token_pointer: r.access_token_pointer,
        refresh_token_pointer: r.refresh_token_pointer,
        account: r.account,
        discovery: r.discovery,
    })
}
impl Provider {
    pub(crate) fn credentials(&self) -> Result<(String, String)> {
        let prefix = self.id.to_ascii_uppercase().replace('-', "_");
        let read = |suffix: &str| {
            std::env::var(format!("ATOMIC_{prefix}_{suffix}"))
                .ok()
                .filter(|v| !v.trim().is_empty())
                .ok_or_else(|| {
                    AtomicServerError::bad_request(format!(
                        "{} sign-in is not configured on this server",
                        self.label
                    ))
                })
        };
        Ok((read("CLIENT_ID")?, read("CLIENT_SECRET")?))
    }
    pub(crate) fn config(&self) -> Result<Config> {
        let prefix = self.id.to_ascii_uppercase().replace('-', "_");
        let read = |suffix: &str| {
            std::env::var(format!("ATOMIC_{prefix}_{suffix}"))
                .ok()
                .filter(|v| !v.trim().is_empty())
                .ok_or_else(|| {
                    AtomicServerError::bad_request(format!(
                        "{} sign-in is not configured on this server",
                        self.label
                    ))
                })
        };
        let (client_id, client_secret) = self.credentials()?;
        let config = Config {
            client_id,
            client_secret,
            redirect_uri: read("REDIRECT_URI")?,
            frontend_origin: read("FRONTEND_ORIGIN")?,
        };
        let callback =
            Url::parse(&config.redirect_uri).map_err(|_| "Invalid OAuth callback configuration")?;
        if !web_url(&callback)
            || callback.path() != format!("/integration-oauth/{}/callback", self.id)
            || callback.query().is_some()
            || callback.fragment().is_some()
        {
            return Err("Invalid OAuth callback configuration".into());
        }
        let frontend =
            Url::parse(&config.frontend_origin).map_err(|_| "Invalid frontend origin")?;
        if !web_url(&frontend) || frontend.origin().ascii_serialization() != config.frontend_origin
        {
            return Err("Invalid frontend origin".into());
        }
        Ok(config)
    }
    pub(crate) fn api_url(&self, path: &str) -> Result<Url> {
        validate_path(path)?;
        let result = self
            .api_origin
            .join(path)
            .map_err(|_| "Invalid provider API path")?;
        if result.origin() != self.api_origin.origin() {
            return Err("Provider API endpoint must remain same-origin".into());
        }
        Ok(result)
    }
    pub(crate) fn account_id<'a>(&self, value: &'a Value) -> Option<&'a str> {
        value.pointer(&self.account.id_pointer)?.as_str()
    }
    pub(crate) fn account_name<'a>(&'a self, value: &'a Value) -> &'a str {
        value
            .pointer(&self.account.name_pointer)
            .and_then(Value::as_str)
            .unwrap_or(&self.account.default_name)
    }
}
fn endpoint(value: &str) -> Result<Url> {
    let u = Url::parse(value).map_err(|_| "Invalid OAuth provider endpoint")?;
    if u.scheme() != "https"
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err("OAuth provider endpoints must be credential-free HTTPS URLs".into());
    }
    Ok(u)
}
fn origin(value: &str) -> Result<Url> {
    let u = endpoint(value)?;
    if u.path() != "/" {
        return Err("OAuth provider API origin must not contain a path".into());
    }
    Ok(u)
}
fn validate_path(path: &str) -> Result<()> {
    if !path.starts_with('/') || path.starts_with("//") || path.contains(['?', '#', '\r', '\n']) {
        return Err("Invalid provider API path".into());
    }
    Ok(())
}
fn web_url(u: &Url) -> bool {
    u.username().is_empty()
        && u.password().is_none()
        && (u.scheme() == "https"
            || (u.scheme() == "http" && matches!(u.host_str(), Some("localhost" | "127.0.0.1"))))
}
pub(crate) fn set_pointer(root: &mut Value, pointer: &str, value: Value) -> Result<()> {
    let keys: Vec<_> = pointer
        .strip_prefix('/')
        .ok_or("Invalid JSON pointer")?
        .split('/')
        .collect();
    let (last, parents) = keys.split_last().ok_or("Invalid JSON pointer")?;
    let mut here = root;
    for key in parents {
        here = here
            .as_object_mut()
            .and_then(|m| m.get_mut(*key))
            .ok_or("Provider request template does not contain configured pointer")?
    }
    here.as_object_mut()
        .ok_or("Provider request pointer is not an object")?
        .insert((*last).to_owned(), value);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_ids_cannot_select_urls() {
        for id in ["", "notion/../../evil", "https://evil.test", "NOTION"] {
            assert!(load(id).is_err())
        }
    }
    #[test]
    fn endpoints_require_clean_https_urls() {
        for u in [
            "http://evil.test/token",
            "https://u:p@evil.test/token",
            "https://evil.test/token?q=secret",
            "https://evil.test/token#x",
        ] {
            assert!(endpoint(u).is_err(), "{u}")
        }
    }
    #[test]
    fn joined_api_paths_stay_on_declared_origin() {
        let p = load("notion").unwrap();
        for path in ["https://evil.test/x", "//evil.test/x", "search?next=x"] {
            assert!(p.api_url(path).is_err(), "{path}")
        }
        assert_eq!(
            p.api_url("/v1/search").unwrap().as_str(),
            "https://api.notion.com/v1/search"
        )
    }
}
