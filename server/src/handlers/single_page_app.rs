use std::fmt::Display;
use std::fmt::Formatter;

use crate::{appstate::AppState, errors::AtomicServerResult};
use actix_web::HttpResponse;

/// Returns the atomic-data-browser single page application
#[tracing::instrument(skip(appstate))]
pub async fn single_page(
    appstate: actix_web::web::Data<AppState>,
    path: actix_web::web::Path<String>,
) -> AtomicServerResult<HttpResponse> {
    let template = include_str!("../../assets_tmp/index.html");
    let subject = format!("{}/{}", appstate.store.get_server_url(), path);
    let meta_tags: MetaTags = if let Ok(resource) =
        appstate
            .store
            .get_resource_extended(&subject, true, &ForAgent::Public)
    {
        resource.into()
    } else {
        MetaTags::default()
    };

    let script = format!("<script>{}</script>", appstate.config.opts.script);
    let body = template
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
        .append_header(("Vary", "Accept"))
        .body(body);

    Ok(resp)
}

use atomic_lib::agents::ForAgent;
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

impl From<Resource> for MetaTags {
    fn from(r: Resource) -> Self {
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
        let json = if let Ok(serialized) = r.to_json_ad() {
            // TODO: also fetch the parents for extra fast first renders.
            Some(serialized)
        } else {
            None
        };
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
        let image = &self.image;
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

fn escape_html(s: &str) -> String {
    s.replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('&', "&amp;")
        .replace('\'', "&#x27;")
        .replace('"', "&quot;")
        .replace('/', "&#x2F;")
}

#[cfg(test)]
mod test {
    use super::MetaTags;

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
