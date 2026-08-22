use std::path::PathBuf;

use actix_web::{http::header, web, HttpResponse};
use atomic_lib::{db::plugin_meta::PluginMetaKey, hierarchy::check_read, urls, Storelike, Subject, Value};
use base64::{engine::general_purpose, Engine as _};

use crate::{
    appstate::AppState, context::RequestContext, errors::{AtomicServerError, AtomicServerResult},
    helpers::get_client_agent,
};

#[derive(serde::Deserialize, Debug)]
pub struct PluginUiQuery {
    pub drive: String,
    /// Either `namespace.name` of an installed plugin, or the subject of a
    /// plugin resource on the drive.
    pub plugin: String,
    pub format: String,
    /// Required when `plugin` is a subject: a null-origin iframe cannot sign a
    /// request, so the authenticated parent mints it a capability instead.
    pub token: Option<String>,
}

/// A plugin whose source lives in the drive rather than on the filesystem.
///
/// Told apart by shape: an installed plugin is `namespace.name`, and a subject
/// is a URL or a DID. Both have dots, neither has a scheme separator.
fn is_subject(plugin: &str) -> bool {
    plugin.contains(':')
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MintTokenBody {
    pub drive: String,
    pub plugin: String,
}

#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MintedToken {
    pub token: String,
    pub expires_at: i64,
}

/// Mints the capability an iframe needs to read one plugin's source.
///
/// Takes read rights, not write: opening a view is reading its code. The check
/// is against the requesting agent, so a token can never widen what the person
/// who asked for it could already see.
#[tracing::instrument(skip(appstate, body, req))]
pub async fn handle_mint_view_token(
    appstate: web::Data<AppState>,
    body: web::Json<MintTokenBody>,
    req: actix_web::HttpRequest,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    if !is_subject(&body.plugin) {
        return Err(AtomicServerError::bad_request(
            "Only a plugin stored in the drive needs a token",
        ));
    }

    let store = &appstate.store;
    let resource = store.get_resource(&body.plugin.as_str().into()).await?;

    let path_and_query = req
        .head()
        .uri
        .path_and_query()
        .ok_or("Path must be given")?
        .to_string();
    let signed_subject =
        atomic_lib::Subject::from_raw(&path_and_query, None).resolve(&context.origin);

    let agent = get_client_agent(req.headers(), &appstate, &signed_subject).await?;
    check_read(store, &resource, &agent).await?;

    let now = atomic_lib::utils::now();
    let token = appstate.view_tokens.mint(&body.drive, &body.plugin, now);

    Ok(HttpResponse::Ok().json(MintedToken {
        token,
        expires_at: now + crate::plugins::view_token::TTL_MS,
    }))
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

/// The `plugin` query parameter is `namespace.name`, both identifiers being
/// `[A-Za-z0-9_-]` (see `validate_plugin_identifiers`). Anything else could
/// steer the file lookup below out of the plugin directory.
fn split_plugin_name(plugin: &str) -> AtomicServerResult<(&str, &str)> {
    let (namespace, name) = plugin
        .split_once('.')
        .ok_or("Invalid plugin name, expected `namespace.name`")?;
    atomic_lib::db::plugin_meta::validate_plugin_identifiers(namespace, name)?;
    Ok((namespace, name))
}

pub fn get_plugin_file_path(
    appstate: &AppState,
    drive_subject: &str,
    plugin_name: &str,
    format: &str,
) -> AtomicServerResult<PathBuf> {
    split_plugin_name(plugin_name)?;
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
/// server. The parent fetches private assets with signed requests, then hands
/// their contents to this shell. Only messages from that parent can install
/// the module, which is locked to a fresh per-response nonce. No credentials
/// are exposed to the null-origin plugin (see PluginView.tsx).
fn render_plugin_ui_html(nonce: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Plugin</title>
<style id="__atomic_theme"></style>
<script nonce="{nonce}">
var loaded = false;
window.addEventListener('message', function (e) {{
  if (e.source !== window.parent) return;
  if (e.data && e.data.type === '__atomic_style') {{
    var s = document.getElementById('__atomic_theme');
    if (s) s.textContent = e.data.css;
  }}
  if (!loaded && e.data && e.data.type === '__atomic_plugin_assets' &&
      typeof e.data.js === 'string' && typeof e.data.css === 'string') {{
    loaded = true;
    var style = document.createElement('style');
    style.textContent = e.data.css;
    document.head.appendChild(style);
    var script = document.createElement('script');
    script.type = 'module';
    script.nonce = '{nonce}';
    script.textContent = e.data.js;
    document.head.appendChild(script);
  }}
}});
if (window.parent) window.parent.postMessage({{ type: '__atomic_plugin_ready' }}, '*');
</script>
</head>
<body><div id="root"></div></body>
</html>"#
    )
}

fn render_drive_plugin_ui_html(query_string: &str, css_exists: bool, nonce: &str) -> String {
    render_drive_plugin_ui_html_with(query_string, css_exists, nonce, false)
}

/// `calls_view`: a plugin whose source is in the drive exports `view` and is
/// called, rather than executing on import. That is what makes it writable by
/// someone who has never seen this codebase — there is no bootstrap to
/// reproduce, just a function that receives what it needs.
fn render_drive_plugin_ui_html_with(
    query_string: &str,
    css_exists: bool,
    nonce: &str,
    calls_view: bool,
) -> String {
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

    let script = if calls_view {
        // Failures surface in the frame instead of only in a console nobody
        // has open: a plugin that throws on load would otherwise render as a
        // blank panel, which reads as "the host is broken".
        format!(
            r#"<script type="module" nonce="{nonce}">
import * as plugin from "{js_url}";
const root = document.getElementById('root');
try {{
  if (typeof plugin.view !== 'function') {{
    throw new Error('This plugin exports no view() function.');
  }}
  await plugin.view({{ root }});
}} catch (e) {{
  root.textContent = String(e && e.message ? e.message : e);
}}
</script>"#
        )
    } else {
        format!(r#"<script type="module" src="{js_url}" nonce="{nonce}"></script>"#)
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
{script}
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

    // A plugin whose source is in the drive: the token is what stands in for
    // the signature the iframe cannot produce.
    if is_subject(plugin_name) {
        let token = query.token.as_deref().unwrap_or_default();

        if !appstate
            .view_tokens
            .admits(token, drive_subject, plugin_name, atomic_lib::utils::now())
        {
            // Deliberately not "expired" versus "wrong plugin" versus "never
            // existed": the caller holding a token is the only one who needs
            // to know, and they can just mint another.
            return Ok(HttpResponse::Unauthorized()
                .body("This plugin view needs a valid, unexpired token."));
        }

        return serve_drive_plugin(&appstate, plugin_name, format, req.query_string()).await;
    }

    let (namespace, name) = match split_plugin_name(plugin_name) {
        Ok(parts) => parts,
        Err(e) => return Ok(HttpResponse::BadRequest().body(e.message)),
    };

    // `html` is generated (not a file on disk): serve the iframe host document
    // with its own CSP so the plugin script isn't blocked by the parent CSP.
    if format == "html" {
        let nonce = plugin_nonce();
        let body = render_plugin_ui_html(&nonce);
        let csp = format!(
            "sandbox allow-scripts allow-downloads allow-pointer-lock allow-presentation; \
             default-src 'none'; script-src 'nonce-{nonce}'; style-src 'unsafe-inline' 'self'; \
             img-src * data:; connect-src *; font-src *; base-uri 'none'; object-src 'none';"
        );

        return Ok(HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .insert_header(("Content-Security-Policy", csp))
            .body(body));
    }

    // The JS/CSS is served to whoever may read the plugin resource itself,
    // as the same agent that fetches the page — signed headers or the
    // session cookie, like any other handler.
    let store = &appstate.store;
    let origin = RequestContext::new(&req, &appstate).origin;
    let full_url = format!("{}{}", origin, req.uri());
    let for_agent = get_client_agent(req.headers(), &appstate, &full_url).await?;
    let Some(meta) = store.get_plugin_meta(&PluginMetaKey::new(drive_subject, namespace, name))?
    else {
        return Ok(HttpResponse::NotFound().body("Plugin UI file not found"));
    };
    let plugin_resource = store
        .get_resource(&Subject::from(meta.subject.as_str()))
        .await?;
    atomic_lib::hierarchy::check_read(store, &plugin_resource, &for_agent).await?;

    let file_path = get_plugin_file_path(&appstate, drive_subject, plugin_name, format)?;

    if !file_path.exists() {
        // No path in the body: the plugin directory layout is not the
        // caller's business.
        return Ok(HttpResponse::NotFound().body("Plugin UI file not found"));
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

/// Serves a plugin whose source is a property on a resource.
///
/// The bytes come from the store instead of `plugin_path`; everything else —
/// the null-origin iframe, its own CSP, the nonce — is unchanged, because none
/// of that depended on where the source was kept.
///
/// Read as Sudo, having already checked the token: the rights question was
/// settled when the token was minted, against the agent who asked for it. The
/// iframe is not an agent and has nothing of its own to check.
async fn serve_drive_plugin(
    appstate: &AppState,
    plugin: &str,
    format: &str,
    query_string: &str,
) -> AtomicServerResult<HttpResponse> {
    if format == "html" {
        let nonce = plugin_nonce();
        // No stylesheet: a plugin in the drive is one module. Its styles belong
        // in it, next to the markup they describe.
        let body = render_drive_plugin_ui_html_with(query_string, false, &nonce, true);
        let csp = format!(
            "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'unsafe-inline' 'self'; \
             img-src * data:; connect-src *; font-src *; base-uri 'none'; object-src 'none';"
        );

        return Ok(HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .insert_header(("Content-Security-Policy", csp))
            .body(body));
    }

    if format != "js" {
        return Err(AtomicServerError::bad_request(
            "A plugin stored in the drive is served as one module",
        ));
    }

    let resource = appstate
        .store
        .get_resource(&plugin.into())
        .await
        .map_err(|e| format!("{plugin} could not be read: {e}"))?;

    let source = source_of(appstate, &resource)
        .await
        .ok_or_else(|| AtomicServerError::bad_request("This plugin has no source"))?;

    Ok(HttpResponse::Ok()
        .content_type("application/javascript")
        .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
        .body(source))
}

/// A plugin's source, found through the drive's own vocabulary.
///
/// `plugin-source` is created per drive, so its subject is not a constant the
/// server can hold — the same reason the scheduler resolves it this way. The
/// plugin's parent may be the drive, or an app that sits on the drive, so walk
/// up until something answers with an ontology.
async fn source_of(appstate: &AppState, resource: &atomic_lib::Resource) -> Option<String> {
    // Two hops covers plugin → app → drive. More than that is a hierarchy
    // nobody built on purpose, and an unbounded walk here is a cycle away from
    // hanging the request.
    let mut subject = resource.get(urls::PARENT).ok()?.to_string();

    for _ in 0..3 {
        if let Some(terms) = crate::plugins::scheduler::drive_terms(&appstate.store, &subject).await
        {
            if let Some(property) = terms.property("plugin-source") {
                return resource.get(property).ok().map(|value| value.to_string());
            }
        }

        let parent = appstate
            .store
            .get_resource(&subject.as_str().into())
            .await
            .ok()?;
        subject = parent.get(urls::PARENT).ok()?.to_string();
    }

    None
}

/// Lists the UI plugins on a drive that the requesting agent may read. The
/// list used to be built as `Sudo`, which showed every plugin on the drive
/// to anyone who asked.
pub async fn handle_plugin_list(
    _path: Option<web::Path<String>>,
    appstate: web::Data<AppState>,
    query: web::Query<UIPluginListQuery>,
    req: actix_web::HttpRequest,
) -> AtomicServerResult<HttpResponse> {
    let store = &appstate.store;
    let drive_subject = &query.drive;

    let origin = RequestContext::new(&req, &appstate).origin;
    let full_url = format!("{}{}", origin, req.uri());
    let for_agent = get_client_agent(req.headers(), &appstate, &full_url).await?;

    let plugins = store.get_class_extenders_on_drive(drive_subject);
    let mut plugin_list: Vec<UIPluginListItem> = vec![];

    for plugin in plugins {
        let Some(subject) = plugin.subject else {
            continue;
        };

        let resource = match store
            .get_resource_extended(&subject.into(), true, &for_agent)
            .await
        {
            Ok(response) => response.to_single(),
            Err(e) => {
                tracing::debug!("plugin-list: skipping plugin {}: {}", for_agent, e);
                continue;
            }
        };

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
