//! Full-text search over the KV inverted index in `atomic_lib::search`.
//! The index updates on every commit. `--rebuild-indexes search` rebuilds it.

use crate::{appstate::AppState, context::RequestContext, errors::AtomicServerResult};
use actix_web::{web, HttpResponse};
use atomic_lib::{client::search::SearchOpts, urls, Resource, Storelike};
use serde::Deserialize;
use serde_with::{formats::CommaSeparator, StringWithSeparator};
use simple_server_timing_header::Timer;

// All this serde stuff is to allow comma separated lists in the query params.
#[serde_with::serde_as]
#[serde_with::skip_serializing_none]
#[derive(Deserialize, Debug)]
pub struct SearchQuery {
    /// The text search query entered by the user in the search box
    pub q: Option<String>,
    /// Maximum amount of results
    pub limit: Option<usize>,
    /// Only include resources that have one of these resources as its ancestor
    #[serde_as(as = "Option<StringWithSeparator::<CommaSeparator, String>>")]
    pub parents: Option<Vec<String>>,
    /// Filter on exact property-value pairs: `prop:"value" AND prop2:"value2"`.
    pub filters: Option<String>,
    pub include: Option<bool>,
}

const DEFAULT_RETURN_LIMIT: usize = 30;
/// Upper bound for a client-supplied `limit`.
const MAX_RETURN_LIMIT: usize = 500;
// We fetch extra documents, as the user may not have the rights to the first ones!
// We filter these results later.
// https://github.com/atomicdata-dev/atomic-server/issues/279.
const UNAUTHORIZED_RESULTS_FACTOR: usize = 3;

/// Parses a search query and responds with a list of resources
#[tracing::instrument(skip(appstate, req))]
pub async fn search_query(
    appstate: web::Data<AppState>,
    params: web::Query<SearchQuery>,
    req: actix_web::HttpRequest,
) -> AtomicServerResult<HttpResponse> {
    let mut timer = Timer::new();
    let limit = match params.limit {
        // Bounded: the caller is unauthenticated, and `limit` feeds
        // multiplications and a result loop below.
        Some(l) if l > 0 => l.min(MAX_RETURN_LIMIT),
        _ => DEFAULT_RETURN_LIMIT,
    };

    let origin = RequestContext::new(&req, &appstate).origin;
    let store = &appstate.store;

    let fetch_limit = (limit * UNAUTHORIZED_RESULTS_FACTOR) as u32;
    let mut opts = SearchOpts {
        limit: Some(fetch_limit),
        parents: params.parents.clone(),
        ..Default::default()
    };
    if let Some(filter) = &params.filters {
        opts.filter_pairs = Some(atomic_lib::search::parse_search_filters(filter));
    }

    let q = params.q.as_deref().unwrap_or("");
    let hits = atomic_lib::search::query(store, q, &opts)?;
    timer.add("execute_query");
    crate::metrics::search_performed();

    let subjects: Vec<String> = hits.into_iter().map(|h| h.subject.to_string()).collect();
    tracing::debug!(
        "search_query: kv index returned {} subjects for params={:?}",
        subjects.len(),
        params
    );

    let path_and_query = req
        .uri()
        .path_and_query()
        .ok_or("Add a query param")?
        .to_string();
    let subject =
        atomic_lib::Subject::from_raw(&path_and_query, store.get_base_domain().as_deref());

    let mut results_resource = crate::plugins::search::search_endpoint()
        .to_resource(store, &subject.to_string())
        .await?;
    results_resource.set_subject(subject.to_string());

    timer.add("get_resources");
    let resources = get_resources(
        req,
        &appstate,
        &format!("{}{}", origin, path_and_query),
        subjects.clone(),
        limit,
    )
    .await?;
    tracing::info!(
        "search_query: after auth filter -> {} resources (was {} subjects)",
        resources.len(),
        subjects.len()
    );

    let filtered_subjects: Vec<String> = resources
        .iter()
        .map(|r| r.get_subject().resolve(&origin))
        .collect();

    results_resource
        .set(
            urls::ENDPOINT_RESULTS.into(),
            filtered_subjects.into(),
            store,
        )
        .await?;

    let mut result_vec: Vec<Resource> = if params.include.unwrap_or(false) {
        resources
    } else {
        vec![]
    };

    result_vec.push(results_resource);

    let mut builder = HttpResponse::Ok();
    builder.append_header(("Server-Timing", timer.header_value()));
    builder.content_type("application/ad+json");

    Ok(builder.body(Resource::vec_to_json_ad(&result_vec, Some(&origin))?))
}

#[tracing::instrument(skip(appstate, req))]
pub async fn get_resources(
    req: actix_web::HttpRequest,
    appstate: &web::Data<AppState>,
    subject: &str,
    subjects: Vec<String>,
    limit: usize,
) -> AtomicServerResult<Vec<Resource>> {
    let mut resources: Vec<Resource> = Vec::new();

    let for_agent = crate::helpers::get_client_agent(req.headers(), appstate, subject).await?;
    for s in subjects {
        match appstate
            .store
            .get_resource_extended(&s.clone().into(), true, &for_agent)
            .await
        {
            Ok(r) => {
                if resources.len() < limit {
                    resources.push(r.to_single());
                } else {
                    break;
                }
            }
            Err(_e) => {
                tracing::debug!("Skipping search result: {} : {}", s, _e);
                continue;
            }
        }
    }
    Ok(resources)
}
