use std::fmt::Display;
use std::fmt::Formatter;

use crate::{appstate::AppState, errors::AtomicServerResult};
use actix_web::HttpResponse;

/// Returns the atomic-data-browser single page application
#[tracing::instrument(skip(appstate))]
pub async fn single_page(
    appstate: actix_web::web::Data<AppState>,
    path: actix_web::web::Path<String>,
    req: actix_web::HttpRequest,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    let origin = context.origin.clone();
    let store = appstate.store.clone_with_url(origin.clone());
    let template = include_str!("../../assets_tmp/index.html");
    let csp_nonce = generate_nonce().map_err(|_e| "Failed to generate nonce")?;
    let subject = format!("{}/{}", origin, path);
    let meta_tags: MetaTags = if let Ok(resource_response) = store
        .get_resource_extended(&subject.clone().into(), true, &ForAgent::Public)
        .await
    {
        MetaTags::from_resource_response(resource_response, &origin)
    } else {
        MetaTags::default()
    };

    let script = format!(
        "<script nonce=\"{}\">{}{}{}</script>",
        csp_nonce,
        home_drive_script(appstate.config.opts.home_drive.as_deref(), &origin),
        sentry_script(appstate.config.opts.sentry_dsn_browser.as_deref()),
        appstate.config.opts.script
    );

    let body = template
        .replace("ATOMICSERVER_NONCE", &csp_nonce)
        .replace("<!-- { inject_html_head } -->", &meta_tags.to_string())
        .replace("<!-- { inject_script } -->", &script);

    let resp = HttpResponse::Ok()
        .content_type("text/html")
        // This prevents the browser from displaying the JSON response upon re-opening a closed tab
        // https://github.com/atomicdata-dev/atomic-server/issues/137
        .insert_header((
            "Cache-Control",
            "no-store, no-cache, must-revalidate, private",
        ))
        .insert_header((
            "Content-Security-Policy",
            format!(
                "script-src 'nonce-{}' 'wasm-unsafe-eval'; worker-src 'self'",
                csp_nonce
            ),
        ))
        .body(body);

    Ok(resp)
}

use atomic_lib::agents::ForAgent;
use atomic_lib::storelike::ResourceResponse;
use atomic_lib::urls;
use atomic_lib::Resource;
use atomic_lib::Storelike;

/* HTML tags for social media and link previews. Also includes JSON-AD body of the requested resource, if publicly available. */
struct MetaTags {
    description: String,
    title: String,
    image: String,
    json: Option<String>,
}

impl MetaTags {
    pub fn from_resource_response(rr: ResourceResponse, origin: &str) -> Self {
        match rr {
            ResourceResponse::Resource(r) => Self::from_resource(r, origin),
            ResourceResponse::ResourceWithReferenced(ref resource, _) => {
                let mut tags: MetaTags = Self::from_resource(resource.clone(), origin);

                // Turns the resource into JSON-AD and base64 encodes it.
                // TODO: also fetch the parents for extra fast first renders!
                let json = rr.to_json_ad(Some(origin)).ok();

                tags.json = json;

                tags
            }
            ResourceResponse::Redirect(target) => MetaTags {
                description: format!("Redirecting to {}", target),
                title: "Redirecting...".into(),
                image: "".into(),
                json: None,
            },
        }
    }
}

impl MetaTags {
    pub fn from_resource(r: Resource, origin: &str) -> Self {
        let description = if let Ok(d) = r.get(urls::DESCRIPTION) {
            d.to_string()
        } else {
            "Open this resource in your browser to view its contents.".to_string()
        };
        let title = if let Ok(d) = r.get(urls::NAME) {
            d.to_string()
        } else {
            "Atomic Server".to_string()
        };
        let image = if let Ok(d) = r.get(urls::DOWNLOAD_URL) {
            // TODO: check if thefile is actually an image
            d.to_string()
        } else {
            "/default_social_preview.jpg".to_string()
        };
        // TODO: also fetch the parents for extra fast first renders!
        let json = r.to_json_ad(Some(origin)).ok();
        Self {
            description,
            title,
            image,
            json,
        }
    }
}

impl Default for MetaTags {
    fn default() -> Self {
        Self {
            description: "Sign in to view this resource".to_string(),
            title: "Atomic Server".to_string(),
            image: "/default_social_preview.jpg".to_string(),
            json: None,
        }
    }
}

impl Display for MetaTags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let description = escape_html(&self.description);
        // `image` is the resource's `downloadUrl`, an ordinary user-settable
        // property, and this page is rendered for public visitors.
        let image = escape_html(&self.image);
        let title = escape_html(&self.title);

        write!(
            f,
            "<meta name=\"description\" content=\"{description}\">
<meta property=\"og:title\" content=\"{title}\">
<meta property=\"og:description\" content=\"{description}\">
<meta property=\"og:image\" content=\"{image}\">
<meta property=\"twitter:card\" content=\"summary_large_image\">
<meta property=\"twitter:title\" content=\"{title}\">
<meta property=\"twitter:description\" content=\"{description}\">
<meta property=\"twitter:image\" content=\"{image}\">"
        )?;
        if let Some(json_unsafe) = &self.json {
            use base64::Engine;
            let json_base64 = base64::engine::general_purpose::STANDARD.encode(json_unsafe);
            write!(
                f,
                "\n<meta property=\"json-ad-initial\" content=\"{}\">",
                json_base64
            )?;
        };
        Ok(())
    }
}

pub(crate) fn escape_html(s: &str) -> String {
    s.replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('&', "&amp;")
        .replace('\'', "&#x27;")
        .replace('"', "&quot;")
        .replace('/', "&#x2F;")
}

/// Declares the configured home Drive to the app, inside the HTML we are
/// already serving.
///
/// The browser must know this before its first render, and it cannot be asked
/// for asynchronously: the Agent lives in IndexedDB, which has no synchronous
/// API, so "is anyone signed in?" is only answerable after an await. A home
/// Drive is shown to everyone regardless of sign-in state, which is exactly
/// what lets the decision be made here — no request, nothing to wait for.
///
/// Empty when unset, which is the default: `/` then keeps sending visitors
/// without an Agent to the welcome flow.
///
/// The subject goes through `serde_json` rather than string interpolation. That
/// alone is not enough: JSON escaping leaves `<` untouched, so a value
/// containing `</script>` would close the tag and everything after it would be
/// markup. Every `<` is therefore rewritten to its unicode escape, which the
/// JS parser reads back as `<` inside the string literal while the HTML parser
/// never sees a tag-closing sequence at all. The value is
/// operator-supplied rather than user-supplied, but it lands inside a script
/// tag either way.
///
/// The subject is resolved against this server's origin before being injected.
///
/// The natural thing to configure for a Drive at the server root is what the
/// store actually holds — `internal:/`. But the browser cannot fetch a bare
/// `internal:` subject: it has no host to send the request to, so it issues no
/// request at all and the page waits forever on "Still loading…", with nothing
/// in the console. Resolving here turns `internal:/` into
/// `https://example.com/`, which the client can fetch, while a `did:ad:`
/// subject resolves to itself and is unaffected.
fn home_drive_script(home_drive: Option<&str>, origin: &str) -> String {
    match home_drive.map(str::trim) {
        Some(drive) if !drive.is_empty() => {
            let resolved = atomic_lib::Subject::from_raw(drive, Some(origin)).resolve(origin);
            match serde_json::to_string(&resolved) {
                Ok(encoded) => {
                    let safe = encoded.replace('<', "\\u003C");
                    format!("window.__ATOMIC_HOME_DRIVE__={safe};")
                }
                Err(_) => String::new(),
            }
        }
        _ => String::new(),
    }
}

/// Hands the front-end its Sentry DSN and environment at runtime, so the same
/// build reports to Sentry only on servers that opted in via
/// `--sentry-dsn-browser`. Empty (no script at all) by default.
fn sentry_script(dsn: Option<&str>) -> String {
    let Some(dsn) = dsn.map(str::trim).filter(|d| !d.is_empty()) else {
        return String::new();
    };
    let environment = std::env::var("SENTRY_ENVIRONMENT").unwrap_or_default();
    let encode = |v: &str| {
        serde_json::to_string(v)
            .map(|e| e.replace('<', "\\u003C"))
            .unwrap_or_else(|_| "\"\"".into())
    };
    format!(
        "window.__ATOMIC_SENTRY__={{dsn:{},environment:{}}};",
        encode(dsn),
        encode(&environment)
    )
}

fn generate_nonce() -> Result<String, ring::error::Unspecified> {
    use base64::{engine::general_purpose, Engine as _};
    use ring::rand::{SecureRandom, SystemRandom};

    let mut nonce_bytes = [0u8; 32];
    let rng = SystemRandom::new();
    rng.fill(&mut nonce_bytes)?;

    Ok(general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes))
}

#[cfg(test)]
mod test {
    use super::{home_drive_script, MetaTags};

    const ORIGIN: &str = "https://example.com";

    #[test]
    fn no_home_drive_by_default() {
        // Every install starts without one; `/` keeps the welcome flow.
        assert_eq!(home_drive_script(None, ORIGIN), "");
        assert_eq!(home_drive_script(Some(""), ORIGIN), "");
        assert_eq!(home_drive_script(Some("   "), ORIGIN), "");
    }

    /// A browser cannot fetch a bare `internal:` subject — it has no host to
    /// send the request to, so it silently issues none and the page hangs on
    /// "Still loading…". `internal:/` is the natural thing to configure for a
    /// Drive at the server root, so resolve it to something fetchable.
    #[test]
    fn root_drive_is_resolved_to_a_fetchable_url() {
        assert_eq!(
            home_drive_script(Some("internal:/"), ORIGIN),
            r#"window.__ATOMIC_HOME_DRIVE__="https://example.com/";"#
        );
        assert!(!home_drive_script(Some("internal:/"), ORIGIN).contains("internal:"));
    }

    #[test]
    fn did_subjects_are_left_alone() {
        // A DID resolves to itself: it is already globally addressable.
        assert_eq!(
            home_drive_script(Some("did:ad:drive:abc"), ORIGIN),
            r#"window.__ATOMIC_HOME_DRIVE__="did:ad:drive:abc";"#
        );
    }

    #[test]
    fn declares_the_configured_drive() {
        assert_eq!(
            home_drive_script(Some("did:ad:drive:abc"), ORIGIN),
            r#"window.__ATOMIC_HOME_DRIVE__="did:ad:drive:abc";"#
        );
        // Whitespace is trimmed before resolution.
        assert_eq!(
            home_drive_script(Some("  internal:/  "), ORIGIN),
            r#"window.__ATOMIC_HOME_DRIVE__="https://example.com/";"#
        );
    }

    #[test]
    fn cannot_break_out_of_the_script_tag() {
        // Operator-supplied, but it still lands inside a <script>. JSON escaping
        // alone leaves `<` intact, so `</script>` would end the element early.
        let out = home_drive_script(Some(r#"a"</script><script>alert(1)</script>"#), ORIGIN);
        assert!(
            !out.contains("</script>"),
            "closed the script tag early: {out}"
        );
        assert!(
            !out.contains('<'),
            "left a raw `<` in the script body: {out}"
        );
        assert!(
            out.starts_with("window.__ATOMIC_HOME_DRIVE__=\""),
            "should still be a plain string assignment: {out}"
        );
    }

    #[test]
    // Malicious test: try escaping html and adding script tag
    fn evil_meta_tags() {
        let html = MetaTags {
            description: "\"<script>alert('evil')</script>\"".to_string(),
            ..Default::default()
        }
        .to_string();
        println!("{}", html);
        assert!(!html.contains("<script>"));
    }
}

#[cfg(test)]
mod sentry_script_tests {
    use super::sentry_script;

    #[test]
    fn empty_without_dsn() {
        assert_eq!(sentry_script(None), "");
        assert_eq!(sentry_script(Some("  ")), "");
    }

    #[test]
    fn escapes_html_in_values() {
        let out = sentry_script(Some("https://k@o.ingest.sentry.io/1</script>"));
        assert!(out.starts_with("window.__ATOMIC_SENTRY__={dsn:\"https://k@o.ingest.sentry.io/1"));
        assert!(!out.contains("</script>"));
        assert!(out.contains("\\u003C/script>"));
    }
}
