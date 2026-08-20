//! Managing the credentials a plugin may spend.
//!
//! Write-only by construction: there is no route that returns a value, because
//! [`Db`] has no method that produces one. Listing describes secrets — name,
//! origins, when and how often used — so a person can decide whether to revoke
//! one without ever seeing it.
//!
//! Authorization is write rights on the plugin resource itself, not merely
//! "the request was signed". A signature identifies an agent; it does not say
//! that agent may touch this drive's plugins.

use actix_web::{web, HttpResponse};
use atomic_lib::{
    db::{
        plugin_meta::PluginMetaKey,
        plugin_secret::{PluginSecret, PluginSecretInfo, PluginSecretKey},
    },
    hierarchy::check_write,
    Storelike,
};

use crate::{appstate::AppState, errors::AtomicServerResult, helpers::get_client_agent};

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SetSecretBody {
    pub drive: String,
    /// Subject of the plugin this secret belongs to.
    pub plugin: String,
    pub name: String,
    pub value: String,
    /// Exact origins, e.g. `https://api.notion.com`.
    pub origins: Vec<String>,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SecretQuery {
    pub drive: String,
    pub plugin: String,
    /// Only for delete.
    pub name: Option<String>,
}

/// What the UI needs in one request: which origins this plugin may reach at
/// all, and which secrets exist. Without the first, "store a secret" is a form
/// with nowhere to send it.
#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SecretsView {
    pub declared_origins: Vec<String>,
    pub secrets: Vec<PluginSecretInfo>,
}

/// A plugin's manifest is keyed by namespace and name, which the plugin
/// resource carries.
fn declared_origins(
    appstate: &AppState,
    drive: &str,
    plugin: &atomic_lib::Resource,
) -> Vec<String> {
    let field = |prop: &str| {
        plugin
            .get(prop)
            .ok()
            .and_then(|v| v.to_string().into())
            .unwrap_or_default()
    };

    let namespace: String = field(atomic_lib::urls::NAMESPACE);
    let name: String = field(atomic_lib::urls::NAME);

    appstate
        .store
        .get_plugin_meta(&PluginMetaKey::new(drive, &namespace, &name))
        .ok()
        .flatten()
        .and_then(|meta| meta.manifest.network)
        .map(|network| network.origins)
        .unwrap_or_default()
}

async fn view(
    appstate: &AppState,
    drive: &str,
    plugin_subject: &str,
) -> AtomicServerResult<SecretsView> {
    let plugin = appstate.store.get_resource(&plugin_subject.into()).await?;

    Ok(SecretsView {
        declared_origins: declared_origins(appstate, drive, &plugin),
        secrets: appstate.store.list_plugin_secrets(drive, plugin_subject)?,
    })
}

/// An origin and nothing else: no path, no query, no credentials in the URL.
///
/// Normalized here rather than at use time so what is stored is exactly what is
/// compared, and a trailing slash cannot make a secret silently unusable.
fn normalize_origin(raw: &str) -> AtomicServerResult<String> {
    let url = url::Url::parse(raw).map_err(|e| format!("`{raw}` is not a URL: {e}"))?;

    match url.scheme() {
        "http" | "https" => {}
        scheme => return Err(format!("`{raw}` uses {scheme}; expected http or https").into()),
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("`{raw}` carries credentials; put them in the secret").into());
    }

    let host = url
        .host_str()
        .ok_or_else(|| format!("`{raw}` has no host"))?;

    Ok(match url.port() {
        Some(port) => format!("{}://{}:{}", url.scheme(), host, port),
        None => format!("{}://{}", url.scheme(), host),
    })
}

/// The caller must be allowed to write the plugin, which is what makes this
/// their secret to set.
async fn authorize(
    appstate: &AppState,
    headers: &actix_web::http::header::HeaderMap,
    plugin: &str,
) -> AtomicServerResult<()> {
    let store = &appstate.store;
    let resource = store.get_resource(&plugin.into()).await?;
    let agent = get_client_agent(headers, appstate, plugin).await?;
    check_write(store, &resource, &agent).await?;

    Ok(())
}

#[tracing::instrument(skip(appstate, body, req))]
pub async fn handle_set_secret(
    appstate: web::Data<AppState>,
    body: web::Json<SetSecretBody>,
    req: actix_web::HttpRequest,
) -> AtomicServerResult<HttpResponse> {
    authorize(&appstate, req.headers(), &body.plugin).await?;

    PluginSecretKey::validate_name(&body.name)?;

    if body.value.is_empty() {
        return Err("A secret needs a value".into());
    }

    if body.origins.is_empty() {
        return Err(
            "A secret needs at least one origin; without one it could never be used".into(),
        );
    }

    let origins = body
        .origins
        .iter()
        .map(|o| normalize_origin(o))
        .collect::<AtomicServerResult<Vec<_>>>()?;

    let key = PluginSecretKey::new(&body.drive, &body.plugin, &body.name);
    let secret = PluginSecret::new(body.value.clone(), origins, atomic_lib::utils::now());

    appstate.store.set_plugin_secret(&key, &secret)?;

    // The name and origins are safe to say; the value never appears in a log.
    tracing::info!(
        plugin = %body.plugin,
        name = %body.name,
        "stored a plugin secret",
    );

    Ok(HttpResponse::Ok().json(view(&appstate, &body.drive, &body.plugin).await?))
}

#[tracing::instrument(skip(appstate, req))]
pub async fn handle_list_secrets(
    appstate: web::Data<AppState>,
    query: web::Query<SecretQuery>,
    req: actix_web::HttpRequest,
) -> AtomicServerResult<HttpResponse> {
    authorize(&appstate, req.headers(), &query.plugin).await?;

    Ok(HttpResponse::Ok().json(view(&appstate, &query.drive, &query.plugin).await?))
}

#[tracing::instrument(skip(appstate, req))]
pub async fn handle_delete_secret(
    appstate: web::Data<AppState>,
    query: web::Query<SecretQuery>,
    req: actix_web::HttpRequest,
) -> AtomicServerResult<HttpResponse> {
    authorize(&appstate, req.headers(), &query.plugin).await?;

    let name = query.name.as_ref().ok_or("Which secret? Pass `name`.")?;

    let key = PluginSecretKey::new(&query.drive, &query.plugin, name);
    appstate.store.delete_plugin_secret(&key)?;

    Ok(HttpResponse::Ok().json(view(&appstate, &query.drive, &query.plugin).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_origin_keeps_scheme_host_and_port_and_nothing_else() {
        assert_eq!(
            normalize_origin("https://api.notion.com/v1/databases").unwrap(),
            "https://api.notion.com",
        );
        assert_eq!(
            normalize_origin("https://api.notion.com/").unwrap(),
            "https://api.notion.com",
        );
        assert_eq!(
            normalize_origin("http://localhost:9883").unwrap(),
            "http://localhost:9883",
        );
        assert_eq!(
            normalize_origin("https://x.test?a=b#c").unwrap(),
            "https://x.test",
        );
    }

    #[test]
    fn a_url_carrying_credentials_is_refused() {
        assert!(normalize_origin("https://user:pw@api.test").is_err());
        assert!(normalize_origin("https://user@api.test").is_err());
    }

    #[test]
    fn only_fetchable_schemes_are_origins() {
        assert!(normalize_origin("file:///etc/passwd").is_err());
        assert!(normalize_origin("ftp://x.test").is_err());
        assert!(normalize_origin("not a url").is_err());
    }
}
