use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use syncables::openapi::{
    load::parse_yaml,
    overlay::{apply_overlay, OverlayDocument},
};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub label: String,
    #[serde(default)]
    pub constants: BTreeMap<String, String>,
    pub client_id_env: String,
    pub client_secret_env: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth {
    pub authorization_url: String,
    pub token_url: String,
    pub scopes: BTreeMap<String, String>,
    #[serde(default, rename = "x-authorization-params")]
    pub params: BTreeMap<String, String>,
}

#[derive(Clone)]
pub struct Integration {
    pub id: String,
    pub document: PathBuf,
    pub overlays: Vec<PathBuf>,
    pub profile: Profile,
    pub oauth: OAuth,
}

// These supplemental overlays are needed until Reflector ships interactive OAuth
// declarations. A folder's own OAuth declarations take precedence.
fn supplement(id: &str) -> Option<&'static str> {
    match id {
        "github" => Some(include_str!("../../integrations/github.json")),
        "google-calendar" => Some(include_str!("../../integrations/google-calendar.json")),
        _ => None,
    }
}

pub fn root() -> PathBuf {
    std::env::var_os("REFLECTOR_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn discover(root: &Path) -> Result<Vec<Integration>> {
    let spec = root.join("spec");
    if !spec.exists() {
        return Ok(vec![]);
    }
    let mut result = vec![];
    for entry in std::fs::read_dir(spec)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        result.push(load(&entry.path())?);
    }
    result.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(result)
}

fn load(folder: &Path) -> Result<Integration> {
    let id = folder
        .file_name()
        .context("integration folder has no name")?
        .to_string_lossy()
        .into_owned();
    let mut documents = vec![];
    for entry in std::fs::read_dir(folder)? {
        let path = entry?.path();
        if path.is_file()
            && path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .contains(".openapi.")
        {
            documents.push(path);
        }
    }
    if documents.len() != 1 {
        bail!("Integration {id} must contain exactly one .openapi.yaml or .openapi.json document");
    }
    let document = documents.remove(0);
    let mut value = parse_yaml(&std::fs::read_to_string(&document)?)?;
    let mut overlays = vec![];
    let overlay_dir = folder.join("overlays");
    if overlay_dir.exists() {
        for entry in std::fs::read_dir(overlay_dir)? {
            let path = entry?.path();
            if path.is_file()
                && matches!(
                    path.extension().and_then(|s| s.to_str()),
                    Some("yaml" | "yml" | "json")
                )
            {
                overlays.push(path);
            }
        }
    }
    overlays.sort();
    for path in &overlays {
        let overlay: OverlayDocument =
            serde_json::from_value(parse_yaml(&std::fs::read_to_string(path)?)?)?;
        value = apply_overlay(&value, &overlay)?;
    }
    let declared_oauth = oauth_flow(&value).cloned();
    let declared_profile = value.get("x-atomic-integration").cloned();
    if let Some(text) = supplement(&id) {
        value = apply_overlay(&value, &serde_json::from_str(text)?)?;
    }
    if let Some(profile) = declared_profile {
        value["x-atomic-integration"] = profile;
    }
    let oauth: OAuth = serde_json::from_value(
        declared_oauth
            .or_else(|| oauth_flow(&value).cloned())
            .context("No OAuth authorizationCode flow declared")?,
    )?;
    let mut profile: Profile = serde_json::from_value(
        value
            .get("x-atomic-integration")
            .cloned()
            .context("Missing x-atomic-integration metadata")?,
    )?;
    let constants_env = format!("{}_API_CONSTANTS", id.replace('-', "_").to_uppercase());
    if let Ok(raw) = std::env::var(constants_env) {
        profile.constants.clear();
        for pair in raw.split(',').filter(|p| !p.trim().is_empty()) {
            let (key, val) = pair
                .split_once('=')
                .context("Expected key=value integration constants")?;
            profile
                .constants
                .insert(key.trim().into(), val.trim().into());
        }
    }
    for endpoint in [&oauth.authorization_url, &oauth.token_url] {
        let url = url::Url::parse(endpoint)?;
        if url.scheme() != "https"
            && !(url.scheme() == "http"
                && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")))
        {
            bail!("OAuth endpoints must use HTTPS (HTTP is allowed for loopback tests)");
        }
    }
    Ok(Integration {
        id,
        document,
        overlays,
        profile,
        oauth,
    })
}

fn oauth_flow(value: &Value) -> Option<&Value> {
    value
        .pointer("/components/securitySchemes")?
        .as_object()?
        .values()
        .find_map(|scheme| scheme.pointer("/flows/authorizationCode"))
}
