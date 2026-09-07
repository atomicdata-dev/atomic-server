use crate::{
    appstate::AppState,
    content_types::get_accept,
    content_types::ContentType,
    errors::AtomicServerResult,
    helpers::{get_client_agent, try_extension},
};
use actix_web::{web, HttpResponse};
use atomic_lib::db::ResolvedTarget;
use simple_server_timing_header::Timer;

/// Respond to a single resource.
/// The URL should match the Subject of the resource.
#[tracing::instrument(skip(appstate, req))]
pub async fn handle_get_resource(
    path: Option<web::Path<String>>,
    appstate: web::Data<AppState>,
    req: actix_web::HttpRequest,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    let mut timer = Timer::new();

    let headers = req.headers();
    let mut content_type = get_accept(headers);
    let origin = context.origin.clone();
    let subject_string = if path.is_some() {
        // Actix Path decodes %2F, but Reflector uses it inside namespace segments.
        // Preserve the signed URL and the stored subject instead of changing identity.
        let mut subj_end_string = req.uri().path().strip_prefix('/').unwrap_or_default();
        if subj_end_string.is_empty() {
            "/".to_string()
        } else {
            if content_type == ContentType::Html {
                if let Some((ext, path)) = try_extension(subj_end_string) {
                    content_type = ext;
                    subj_end_string = path;
                }
            }
            let querystring = if req.query_string().is_empty() {
                "".to_string()
            } else {
                format!("?{}", req.query_string())
            };
            // DID subjects should be used as-is, not prefixed with /
            if subj_end_string.starts_with("did:") {
                format!("{}{}", subj_end_string, querystring)
            } else {
                format!("/{}{}", subj_end_string, querystring)
            }
        }
    } else {
        "/".to_string()
    };

    let subject = atomic_lib::Subject::from_raw(&subject_string, None);

    timer.add("parse_headers");

    // Extract host for drive mapping, stripping port if present
    let host = headers
        .get("Host")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h))
        .unwrap_or("localhost");

    let full_url = if subject_string.starts_with('/') {
        format!("{}{}", origin, subject_string)
    } else {
        format!("{}/{}", origin, subject_string)
    };
    let for_agent = get_client_agent(headers, &appstate, &full_url).await?;
    timer.add("get_agent");

    let resolved: ResolvedTarget = appstate
        .store
        .resolve_request_target(&subject, host, &subject_string, &origin)
        .await?;
    let resource_response = appstate
        .store
        .fetch_resource_with_did_fallback(&resolved.subject, &origin, &for_agent)
        .await?;

    if let atomic_lib::storelike::ResourceResponse::Redirect(target) = resource_response {
        return Ok(HttpResponse::SeeOther()
            .append_header(("Location", target))
            .finish());
    }

    let mut builder = HttpResponse::Ok();
    if let Some(resp_subject) = resource_response.get_subject() {
        if let atomic_lib::Subject::Did { .. } = resp_subject {
            builder.append_header((
                "Link",
                format!("<{}>; rel=\"canonical\"", resp_subject.as_str()),
            ));
        }
    }

    let mut resource = resource_response.to_single();

    if let Some(redirect) = resolved.alias_subject {
        let old_subject: &str = resource.get_subject().as_str();
        tracing::debug!(
            "Aliasing resource {} to requested subject {}",
            old_subject,
            redirect
        );
        resource.set_subject(redirect);
        builder.append_header((
            "Warning",
            "299 - \"Resource resolved via alias. Identity is the canonical DID.\"",
        ));
    }

    builder.append_header(("Content-Type", content_type.to_mime()));
    // This prevents the browser from displaying the JSON response upon re-opening a closed tab
    // https://github.com/atomicdata-dev/atomic-server/issues/137
    builder.append_header((
        "Cache-Control",
        "no-store, no-cache, must-revalidate, private",
    ));

    let store = appstate.store.clone_with_url(origin.clone());

    crate::metrics::resource_fetched_http();

    let response_body = match content_type {
        ContentType::Json => resource.to_json(&store, Some(&origin)).await?,
        ContentType::JsonLd => resource.to_json_ld(&store, Some(&origin)).await?,
        ContentType::JsonAd => resource.to_json_ad(Some(&origin))?,
        ContentType::Html => resource.to_json_ad(Some(&origin))?,
        ContentType::Turtle | ContentType::NTriples => {
            let atoms = resource.to_atoms();
            atomic_lib::serialize::atoms_to_ntriples(atoms, &store).await?
        }
    };

    timer.add("serialize");
    Ok(builder.body(response_body))
}
