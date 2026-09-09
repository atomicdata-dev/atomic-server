use crate::{appstate::AppState, errors::AtomicServerResult, handlers::search::get_resources};
use actix_web::{web, HttpResponse};
use arrow::array::Array;
use atomic_lib::{urls, Resource, Storelike};
use lancedb::query::{ExecutableQuery, QueryBase, Select};
use lancedb::DistanceType;
use serde::Deserialize;
use simple_server_timing_header::Timer;

#[serde_with::serde_as]
#[serde_with::skip_serializing_none]
#[derive(Deserialize, Debug)]
pub struct VectorSearchQuery {
    /// The text search query entered by the user
    pub q: Option<String>,
    /// Maximum amount of results
    pub limit: Option<usize>,
    pub include: Option<bool>,
    /// Optional hybrid search (Vector + Full-Text Search) with Reciprocal Rank Fusion (RRF)
    pub text_q: Option<String>,
    /// Optional reranking for better result accuracy
    pub rerank: Option<bool>,
    /// Only include resources that have one of these resources as its ancestor
    #[serde_as(
        as = "Option<serde_with::StringWithSeparator::<serde_with::formats::CommaSeparator, String>>"
    )]
    pub parents: Option<Vec<String>>,
    /// Filter by class
    #[serde_as(
        as = "Option<serde_with::StringWithSeparator::<serde_with::formats::CommaSeparator, String>>"
    )]
    pub is_a: Option<Vec<String>>,
}

const DEFAULT_RETURN_LIMIT: usize = 30;
/// Upper bound for a client-supplied `limit`.
const MAX_RETURN_LIMIT: usize = 500;

/// Quote `value` as a SQL string literal for the LanceDB/DataFusion filter.
/// `parents` and `is_a` come straight from the query string; unescaped, a
/// value like `x') OR true --` rewrites the predicate.
fn sql_string_literal(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "''"))
}
const UNAUTHORIZED_RESULTS_FACTOR: usize = 3;

/// Parses a vector search query and responds with a list of resources
#[tracing::instrument(skip(appstate, req))]
pub async fn vector_search_query(
    appstate: web::Data<AppState>,
    params: web::Query<VectorSearchQuery>,
    req: actix_web::HttpRequest,
) -> AtomicServerResult<HttpResponse> {
    let mut timer = Timer::new();
    let store = &appstate.store;
    let limit = match params.limit {
        // Bounded: the caller is unauthenticated, and `limit` feeds
        // multiplications and a result loop below.
        Some(l) if l > 0 => l.min(MAX_RETURN_LIMIT),
        _ => DEFAULT_RETURN_LIMIT,
    };

    let fetch_limit = if params.rerank.unwrap_or(false) {
        limit * 5
    } else {
        limit
    };

    let mut subjects: Vec<String> = Vec::new();
    let mut chunks_map: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    if !appstate.vector_search_state.is_enabled() {
        return Err("Vector search is disabled on this server".into());
    }

    if let Some(q) = &params.q {
        timer.add("embed_query");
        let embeddings = appstate
            .vector_search_state
            .embed_chunks(&[q.clone()])
            .await
            .map_err(|e| format!("Error embedding query: {}", e))?;

        if let Some(query_embedding) = embeddings.into_iter().next() {
            timer.add("search_lancedb");

            let mut filter_exprs = Vec::new();

            if let Some(parents) = &params.parents {
                if !parents.is_empty() {
                    let parent_list = parents
                        .iter()
                        .map(|p| sql_string_literal(p))
                        .collect::<Vec<_>>()
                        .join(", ");
                    filter_exprs.push(format!("array_has_any(hierarchy, [{}])", parent_list));
                }
            }

            if let Some(classes) = &params.is_a {
                if !classes.is_empty() {
                    let class_list = classes
                        .iter()
                        .map(|c| sql_string_literal(c))
                        .collect::<Vec<_>>()
                        .join(", ");
                    filter_exprs.push(format!("array_has_any(is_a, [{}])", class_list));
                }
            }

            let mut query = appstate
                .vector_search_state
                .table
                .query()
                .select(Select::columns(&["subject", "text_chunk"]))
                .nearest_to(query_embedding)
                .map_err(|e| format!("Failed to create vector query: {}", e))?;

            if let Some(text_q) = &params.text_q {
                query = query
                    .full_text_search(lancedb::index::scalar::FullTextSearchQuery::new(
                        text_q.clone(),
                    ))
                    .rerank(std::sync::Arc::new(
                        lancedb::rerankers::rrf::RRFReranker::new(60.0),
                    ));
            }

            let mut query = query
                .distance_type(DistanceType::Cosine)
                .limit(fetch_limit * UNAUTHORIZED_RESULTS_FACTOR);

            if !filter_exprs.is_empty() {
                let filter_str = filter_exprs.join(" AND ");
                query = query.only_if(filter_str);
            }

            let mut stream = query
                .execute()
                .await
                .map_err(|e| format!("Failed to execute vector query: {}", e))?;

            use futures::StreamExt;
            while let Some(batch_result) = stream.next().await {
                let batch = batch_result
                    .map_err(|e| format!("Error reading vector search result batch: {}", e))?;
                if let (Some(subject_array), Some(chunk_array)) = (
                    batch.column_by_name("subject"),
                    batch.column_by_name("text_chunk"),
                ) {
                    if let (Some(subject_strings), Some(chunk_strings)) = (
                        subject_array
                            .as_any()
                            .downcast_ref::<arrow::array::StringArray>(),
                        chunk_array
                            .as_any()
                            .downcast_ref::<arrow::array::StringArray>(),
                    ) {
                        for i in 0..subject_strings.len() {
                            if !subject_strings.is_null(i) {
                                let subject = subject_strings.value(i).to_string();
                                let chunk = chunk_strings.value(i).to_string();
                                if !subjects.contains(&subject) {
                                    subjects.push(subject.clone());
                                    chunks_map.insert(subject, chunk);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let subject = format!(
        "{}{}",
        store.get_server_url(),
        req.uri().path_and_query().ok_or("Add a query param")?
    );

    let mut results_resource = crate::plugins::vector_search::vector_search_endpoint()
        .to_resource(store, &subject)
        .await?;
    results_resource.set_subject(subject.clone());

    timer.add("get_resources");
    // Get all resources returned by the search, this also performs authorization checks!
    let mut resources =
        get_resources(req, &appstate, &subject, subjects.clone(), fetch_limit).await?;

    // Convert the list of resources back into subjects.
    // These filtered lists will not contain any resources that the user does not have access to.
    let filtered_subjects: Vec<String> = resources
        .iter()
        .map(|r| r.get_subject().to_string())
        .collect();

    let filtered_chunks: Vec<String> = filtered_subjects
        .iter()
        .filter_map(|s| chunks_map.get(s).cloned())
        .collect();

    if params.rerank.unwrap_or(false) {
        if let Some(q) = &params.q {
            timer.add("rerank");

            if !filtered_chunks.is_empty() {
                let rerank_results = {
                    let rerank_model = appstate
                        .vector_search_state
                        .rerank_model
                        .as_ref()
                        .ok_or("Reranking is not available (vector search disabled)")?;
                    let mut rerank_model = rerank_model.lock().await;

                    #[cfg(target_os = "macos")]
                    {
                        objc::rc::autoreleasepool(|| {
                            rerank_model.rerank(q.clone(), &filtered_chunks, false, None)
                        })
                        .map_err(|e| format!("Error reranking results: {}", e))?
                    }

                    #[cfg(not(target_os = "macos"))]
                    {
                        rerank_model
                            .rerank(q.clone(), &filtered_chunks, false, None)
                            .map_err(|e| format!("Error reranking results: {}", e))?
                    }
                };

                resources = rerank_results
                    .into_iter()
                    .take(limit)
                    .map(|res| resources[res.index].clone())
                    .collect();
            }
        }
    }

    results_resource
        .set(
            urls::ENDPOINT_RESULTS.into(),
            filtered_subjects.into(),
            store,
        )
        .await?;

    results_resource
        .set(
            urls::SEARCH_CHUNKS.into(),
            atomic_lib::Value::Json(filtered_chunks.into()),
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

    Ok(builder.body(Resource::vec_to_json_ad(&result_vec, None)?))
}
