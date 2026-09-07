use std::path::PathBuf;

use actix_web::{http::header, web, HttpResponse};
use atomic_lib::{agents::ForAgent, db::plugin_meta::PluginMetaKey, urls, Storelike, Value};
use base64::{engine::general_purpose, Engine as _};

use crate::{appstate::AppState, errors::AtomicServerResult};

#[derive(serde::Deserialize, Debug)]
pub struct PluginUiQuery {
    pub drive: String,
    pub plugin: String,
    pub format: String,
}

#[derive(serde::Deserialize, Debug)]
pub struct UIPluginListQuery {
    pub drive: String,
}

#[derive(serde::Serialize, Debug)]
pub struct PluginUIManifest {
    pub css: bool,
}

#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct UIPluginListItem {
    pub plugin: String,
    pub classes: Vec<String>,
    pub ui_manifest: PluginUIManifest,
    pub resource: String,
}

pub fn get_plugin_file_path(
    appstate: &AppState,
    drive_subject: &str,
    plugin_name: &str,
    format: &str,
) -> AtomicServerResult<PathBuf> {
    let encoded_drive = general_purpose::URL_SAFE.encode(drive_subject);

    let plugin_dir = appstate
        .config
        .plugin_path
        .join("class-extenders")
        .join("scoped")
        .join(encoded_drive);

    let extension = match format {
        "js" => "js",
        "css" => "css",
        _ => return Err("Invalid format".into()),
    };

    let file_name = format!("{}.ui.{}", plugin_name, extension);
    let file_path = plugin_dir.join(file_name);

    Ok(file_path)
}

/// Generates a random CSP nonce for the plugin iframe document.
fn plugin_nonce() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0u8; 32];
    // Falls back to a fixed (still-functional) value only if the RNG fails,
    // which in practice never happens.
    if SystemRandom::new().fill(&mut bytes).is_err() {
        return "atomic-plugin-nonce".to_string();
    }
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Builds the HTML document that hosts a plugin's custom view. Served as a real
/// network response (not a client-side `srcdoc`) so it gets its OWN
/// Content-Security-Policy instead of inheriting the parent SPA's nonce-locked
/// CSP — otherwise the plugin's `<script>` is blocked on any CSP-enforced
/// server. The plugin script is locked to a fresh per-response nonce; the host
/// SPA hands over theme CSS via `postMessage` (see PluginView.tsx).
fn render_plugin_ui_html(query_string: &str, css_exists: bool, nonce: &str) -> String {
    // The query string is reflected into attributes of a same-origin page,
    // so it must be attribute-escaped; a stray `"` would otherwise close the
    // attribute and inject markup (a `<meta http-equiv=refresh>` is enough
    // to redirect every visitor, CSP or not).
    let query_string = super::single_page_app::escape_html(query_string);
    let js_url = format!(
        "/plugin-ui?{}",
        query_string.replace("format=html", "format=js")
    );
    let css_link = if css_exists {
        let css_url = format!(
            "/plugin-ui?{}",
            query_string.replace("format=html", "format=css")
        );
        format!(r#"<link rel="stylesheet" href="{css_url}" />"#)
    } else {
        String::new()
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Plugin</title>
{css_link}
<style id="__atomic_theme"></style>
<script type="module" src="{js_url}" nonce="{nonce}"></script>
<script nonce="{nonce}">
window.addEventListener('message', function (e) {{
  if (e.data && e.data.type === '__atomic_style') {{
    var s = document.getElementById('__atomic_theme');
    if (s) s.textContent = e.data.css;
  }}
}});
if (window.parent) window.parent.postMessage({{ type: '__atomic_plugin_ready' }}, '*');
</script>
</head>
<body><div id="root"></div></body>
</html>"#
    )
}

/// Retrieves the UI js script for the plugin.
/// It exepcts two query parameters: drive and plugin (namespace.name)
#[tracing::instrument(skip(appstate, req))]
pub async fn handle_plugin_ui(
    _path: Option<web::Path<String>>,
    appstate: web::Data<AppState>,
    query: web::Query<PluginUiQuery>,
    req: actix_web::HttpRequest,
) -> AtomicServerResult<HttpResponse> {
    let drive_subject = &query.drive;
    let plugin_name = &query.plugin;
    let format = &query.format;

    // `html` is generated (not a file on disk): serve the iframe host document
    // with its own CSP so the plugin script isn't blocked by the parent CSP.
    if format == "html" {
        let css_exists =
            get_plugin_file_path(&appstate, drive_subject, plugin_name, "css")?.exists();
        let nonce = plugin_nonce();
        let body = render_plugin_ui_html(req.query_string(), css_exists, &nonce);
        let csp = format!(
            "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'unsafe-inline' 'self'; \
             img-src * data:; connect-src *; font-src *; base-uri 'none'; object-src 'none';"
        );

        return Ok(HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .insert_header(("Content-Security-Policy", csp))
            .body(body));
    }

    let file_path = get_plugin_file_path(&appstate, drive_subject, plugin_name, format)?;

    if !file_path.exists() {
        return Ok(HttpResponse::NotFound()
            .body(format!("Plugin UI file not found: {}", file_path.display())));
    }

    let content = std::fs::read_to_string(&file_path)
        .map_err(|e| format!("Failed to read plugin UI file: {}", e))?;

    let content_type = match format.as_str() {
        "js" => "application/javascript",
        "css" => "text/css",
        _ => return Err("Invalid format".into()),
    };

    Ok(HttpResponse::Ok()
        .content_type(content_type)
        .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
        .body(content))
}

pub async fn handle_plugin_list(
    _path: Option<web::Path<String>>,
    appstate: web::Data<AppState>,
    query: web::Query<UIPluginListQuery>,
    _req: actix_web::HttpRequest,
) -> AtomicServerResult<HttpResponse> {
    let store = &appstate.store;
    let drive_subject = &query.drive;

    let plugins = store.get_class_extenders_on_drive(drive_subject);
    let mut plugin_list: Vec<UIPluginListItem> = vec![];

    for plugin in plugins {
        let Some(subject) = plugin.subject else {
            continue;
        };

        let resource = store
            .get_resource_extended(&subject.into(), true, &ForAgent::Sudo)
            .await?
            .to_single();

        let Ok(Value::String(name)) = resource.get(urls::NAME) else {
            continue;
        };

        let Ok(Value::String(namespace)) = resource.get(urls::NAMESPACE) else {
            continue;
        };

        let plugin_name = format!("{}.{}", namespace, name);
        let js_file_path = get_plugin_file_path(&appstate, drive_subject, &plugin_name, "js")?;
        let css_file_path = get_plugin_file_path(&appstate, drive_subject, &plugin_name, "css")?;

        let Some(meta) =
            store.get_plugin_meta(&PluginMetaKey::new(drive_subject, namespace, name))?
        else {
            tracing::warn!("Plugin {} has no metadata", plugin_name);
            continue;
        };

        if !js_file_path.exists() {
            continue;
        }

        plugin_list.push(UIPluginListItem {
            plugin: plugin_name,
            classes: plugin.classes,
            ui_manifest: PluginUIManifest {
                css: css_file_path.exists(),
            },
            resource: meta.subject,
        });
    }

    Ok(HttpResponse::Ok().json(plugin_list))
}
