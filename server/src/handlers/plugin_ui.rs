use std::path::PathBuf;

use actix_web::{http::header, web, HttpResponse};
use atomic_lib::{
    agents::ForAgent, db::plugin_meta::PluginMetaKey, hierarchy::check_read, urls, Storelike, Value,
};
use base64::{engine::general_purpose, Engine as _};

use crate::{
    appstate::AppState,
    errors::{AtomicServerError, AtomicServerResult},
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
    render_plugin_ui_html_with(query_string, css_exists, nonce, false)
}

/// `calls_view`: a plugin whose source is in the drive exports `view` and is
/// called, rather than executing on import. That is what makes it writable by
/// someone who has never seen this codebase — there is no bootstrap to
/// reproduce, just a function that receives what it needs.
fn render_plugin_ui_html_with(
    query_string: &str,
    css_exists: bool,
    nonce: &str,
    calls_view: bool,
) -> String {
    let js_url = format!(
        "/plugin-ui?{}",
        query_string.replace("format=html", "format=js")
    );
    let client_url = format!(
        "/plugin-ui?{}",
        query_string.replace("format=html", "format=client")
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
        //
        // They are also reported to the host, because rendering the message
        // here is a dead end: the frame is null-origin, so nothing outside it
        // can read this text, and the person who has to fix the app is on the
        // other side of that boundary.
        format!(
            r#"<script type="module" nonce="{nonce}">
import * as plugin from "{js_url}";
import {{ store }} from "{client_url}";
const root = document.getElementById('root');
try {{
  if (typeof plugin.view !== 'function') {{
    throw new Error('This plugin exports no view() function.');
  }}
  await plugin.view({{ root, store }});
  // Says it got to the end, and how much it drew. Silence is not success: an
  // app whose view() resolves having rendered nothing is a blank panel, which
  // looks exactly like one that never loaded. The count tells those apart.
  if (window.parent) {{
    window.parent.postMessage({{
      type: '__atomic_plugin_rendered',
      children: root.childElementCount,
    }}, '*');
  }}
}} catch (e) {{
  root.textContent = String(e && e.message ? e.message : e);
  window.__atomicReportError(e, 'load');
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
// An app fails where the person who can fix it cannot see it. The frame is
// null-origin by design, so its console belongs to nobody: a throw in a click
// handler leaves a dead button and no trace anywhere reachable. Every error
// route out of the frame therefore ends here, and goes to the host.
//
// This block sits after the module script in the document but runs before it:
// a `type=module` script is deferred, a classic inline one is not. So the
// reporter exists by the time a load-time throw looks for it.
window.__atomicReportError = function (error, phase) {{
  if (!window.parent) return;

  var message = error && error.message ? error.message : String(error);

  window.parent.postMessage({{
    type: '__atomic_plugin_error',
    phase: phase || 'runtime',
    message: message,
    // The stack names the line, which is the difference between "it broke"
    // and a fix. It describes only the app's own source, which its author is
    // already allowed to read.
    stack: error && error.stack ? String(error.stack) : undefined,
  }}, '*');
}};

window.addEventListener('error', function (e) {{
  window.__atomicReportError(e.error || e.message, 'runtime');
}});

// A rejected promise nobody caught is the common shape here: the host refuses
// a write the app is not allowed to make, and an app that never awaited the
// refusal simply does nothing with no explanation.
window.addEventListener('unhandledrejection', function (e) {{
  window.__atomicReportError(e.reason, 'runtime');
}});

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
        let body = render_plugin_ui_html_with(query_string, false, &nonce, true);
        let csp = format!(
            "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'unsafe-inline' 'self'; \
             img-src * data:; connect-src *; font-src *; base-uri 'none'; object-src 'none';"
        );

        return Ok(HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .insert_header(("Content-Security-Policy", csp))
            .body(body));
    }

    // The data API the view is handed. Embedded rather than generated, so it
    // stays a real JS file that can be linted and read.
    if format == "client" {
        return Ok(HttpResponse::Ok()
            .content_type("application/javascript")
            .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
            .body(include_str!("../plugins/assets/view-client.js")));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// An app's frame is null-origin, so its console is reachable by nobody:
    /// whatever it prints there, the person who could fix the app never sees.
    /// Every way out of the frame therefore has to end in a message to the
    /// host, and these are the three ways out.
    #[test]
    fn every_route_out_of_a_broken_app_reaches_the_host() {
        let html = render_plugin_ui_html_with("format=html", false, "n0nce", true);

        // Threw while opening.
        assert!(html.contains("window.__atomicReportError(e, 'load')"));
        // Threw while being used — the dead button.
        assert!(html.contains("window.addEventListener('error'"));
        // Refused by the host and never awaited, which is what a write outside
        // the app's own subtree looks like from in there.
        assert!(html.contains("window.addEventListener('unhandledrejection'"));

        assert!(html.contains("'__atomic_plugin_error'"));
    }

    /// Success has to be reported too. Without it, "no error yet" is the only
    /// evidence a caller has, and that is indistinguishable from a frame that
    /// is still loading — or one that rendered nothing at all.
    #[test]
    fn an_app_that_worked_says_so_and_says_how_much_it_drew() {
        let html = render_plugin_ui_html_with("format=html", false, "n0nce", true);

        assert!(html.contains("'__atomic_plugin_rendered'"));
        assert!(html.contains("root.childElementCount"));
    }

    /// The reporter is declared after the module script in the document but has
    /// to exist before it runs, which it does only because `type=module` defers
    /// and a classic inline script does not. Reordering these silently loses
    /// every load-time error.
    #[test]
    fn the_reporter_is_defined_by_the_time_a_load_error_looks_for_it() {
        let html = render_plugin_ui_html_with("format=html", false, "n0nce", true);

        let reporter = html
            .find("window.__atomicReportError = function")
            .expect("reporter is defined");

        // Which <script> does it live in? The one that opens last before it.
        let opening = html[..reporter]
            .rfind("<script")
            .expect("the reporter is inside a script tag");
        let tag_end = html[opening..]
            .find('>')
            .map(|i| opening + i)
            .expect("that script tag is closed");

        assert!(
            !html[opening..tag_end].contains("type=\"module\""),
            "the reporter must stay in a classic script. A module defers, so \
             moving it there would leave load-time throws with nothing to call."
        );
    }
}
