//! Full-text search is achieved with the Tantivy crate.
//! The index is built whenever --rebuild-index is passed,
//! or after a commit is processed by the CommitMonitor.

use crate::{
    appstate::AppState,
    errors::{AtomicServerError, AtomicServerResult},
    search::{resource_to_facet, Fields},
};
use actix_web::{web, HttpResponse};
use atomic_lib::{errors::AtomicResult, urls, Db, Resource, Storelike};
use serde::Deserialize;
use simple_server_timing_header::Timer;
use tantivy::{
    collector::TopDocs,
    query::{BooleanQuery, BoostQuery, Occur, Query, QueryParser, TermQuery},
    schema::IndexRecordOption,
    tokenizer::Tokenizer,
    Term,
};
use tracing::instrument;

type Queries = Vec<(Occur, Box<dyn Query>)>;

#[derive(Deserialize, Debug)]
pub struct SearchQuery {
    /// The text search query entered by the user in the search box
    pub q: Option<String>,
    /// Include the full resources in the response
    pub include: Option<bool>,
    /// Maximum amount of results
    pub limit: Option<usize>,
    /// Only include resources that have this resource as its ancestor
    pub parent: Option<String>,
    /// Filter based on props, using tantivy QueryParser syntax.
    /// e.g. `prop:val` or `prop:val~1` or `prop:val~1 AND prop2:val2`
    /// See https://docs.rs/tantivy/latest/tantivy/query/struct.QueryParser.html
    pub filters: Option<String>,
}

const DEFAULT_RETURN_LIMIT: usize = 30;
// We fetch extra documents, as the user may not have the rights to the first ones!
// We filter these results later.
// https://github.com/atomicdata-dev/atomic-data-rust/issues/279.
const UNAUTHORIZED_RESULTS_FACTOR: usize = 3;

/// Parses a search query and responds with a list of resources
#[tracing::instrument(skip(appstate, req))]
pub async fn search_query(
    appstate: web::Data<AppState>,
    params: web::Query<SearchQuery>,
    req: actix_web::HttpRequest,
) -> AtomicServerResult<HttpResponse> {
    let mut timer = Timer::new();
    let store = &appstate.store;
    let searcher = appstate.search_state.reader.searcher();
    let fields = crate::search::get_schema_fields(&appstate.search_state)?;
    let limit = if let Some(l) = params.limit {
        if l > 0 {
            l
        } else {
            DEFAULT_RETURN_LIMIT
        }
    } else {
        DEFAULT_RETURN_LIMIT
    };

    let query = query_from_params(&params, &fields, &appstate)?;
    timer.add("build_query");
    let top_docs = searcher
        .search(
            &query,
            &TopDocs::with_limit(limit * UNAUTHORIZED_RESULTS_FACTOR),
        )
        .map_err(|e| format!("Error with creating search results: {} ", e))?;

    timer.add("execute_query");
    let subjects = docs_to_subjects(top_docs, &fields, &searcher)?;

    // Create a valid atomic data resource.
    // You'd think there would be a simpler way of getting the requested URL...
    let subject = format!(
        "{}{}",
        store.get_self_url().ok_or("No base URL set")?,
        req.uri().path_and_query().ok_or("Add a query param")?
    );

    let mut results_resource = atomic_lib::plugins::search::search_endpoint().to_resource(store)?;
    results_resource.set_subject(subject.clone());

    let resources = get_resources(req, &appstate, &subject, subjects, limit)?;
    timer.add("get_resources");
    results_resource.set_propval(urls::ENDPOINT_RESULTS.into(), resources.into(), store)?;
    let mut builder = HttpResponse::Ok();
    builder.append_header(("Server-Timing", timer.header_value()));

    // TODO: support other serialization options
    Ok(builder.body(results_resource.to_json_ad()?))
}

#[derive(Debug, std::hash::Hash, Eq, PartialEq)]
pub struct StringAtom {
    pub subject: String,
    pub property: String,
    pub value: String,
}

#[instrument(skip(appstate, req))]
fn get_resources(
    req: actix_web::HttpRequest,
    appstate: &web::Data<AppState>,
    subject: &str,
    subjects: Vec<String>,
    limit: usize,
) -> AtomicServerResult<Vec<Resource>> {
    // Default case: return full resources, do authentication
    let mut resources: Vec<Resource> = Vec::new();

    // This is a pretty expensive operation. We need to check the rights for the subjects to prevent data leaks.
    // But we could probably do some things to speed this up: make it async / parallel, check admin rights.
    // https://github.com/atomicdata-dev/atomic-data-rust/issues/279
    // https://github.com/atomicdata-dev/atomic-data-rust/issues/280/
    let for_agent = crate::helpers::get_client_agent(req.headers(), appstate, subject.into())?;
    for s in subjects {
        match appstate
            .store
            .get_resource_extended(&s, true, for_agent.as_deref())
        {
            Ok(r) => {
                if resources.len() < limit {
                    resources.push(r);
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

#[tracing::instrument(skip(appstate))]
fn query_from_params(
    params: &SearchQuery,
    fields: &Fields,
    appstate: &web::Data<AppState>,
) -> AtomicServerResult<impl Query> {
    let mut query_list: Queries = Vec::new();

    if let Some(parent) = &params.parent {
        let query = build_parent_query(parent, fields, &appstate.store)?;

        query_list.push((Occur::Must, Box::new(query)));
    }

    if let Some(q) = &params.q {
        let text_query = build_text_query(fields, q)?;

        query_list.push((Occur::Must, Box::new(text_query)));
    }

    if let Some(filter) = &params.filters {
        let filter_query = BoostQuery::new(
            build_filter_query(fields, filter, &appstate.search_state.index)?,
            20.0,
        );

        query_list.push((Occur::Must, Box::new(filter_query)));
    }

    let query = BooleanQuery::new(query_list);

    Ok(query)
}

/// Performs both fuzzy and exact queries on the text and description fields.
/// Boosts titles and exact matches over descriptions and fuzzy matches.
/// Does not yet search in JSON fields:
/// https://github.com/atomicdata-dev/atomic-data-rust/issues/597
#[tracing::instrument]
fn build_text_query(fields: &Fields, q: &str) -> AtomicResult<impl Query> {
    let mut token_stream = tantivy::tokenizer::SimpleTokenizer.token_stream(q);
    let mut queries: Queries = Vec::new();
    // for every word, create a fuzzy query and an exact query
    token_stream.process(&mut |token| {
        let word = &token.text;
        let title_term = Term::from_field_text(fields.title, word);
        let description_term = Term::from_field_text(fields.description, word);
        let title_fuzzy = tantivy::query::FuzzyTermQuery::new_prefix(title_term.clone(), 1, true);
        let description_fuzzy =
            tantivy::query::FuzzyTermQuery::new_prefix(description_term.clone(), 1, true);
        let title_exact = TermQuery::new(title_term, IndexRecordOption::Basic);
        let description_exact = TermQuery::new(description_term, IndexRecordOption::Basic);

        // Boost the title higher than the description
        queries.push((
            Occur::Should,
            Box::new(BoostQuery::new(Box::new(title_exact), 10.)),
        ));
        queries.push((
            Occur::Should,
            Box::new(BoostQuery::new(Box::new(description_exact), 2.0)),
        ));

        // Rank exact higher than fuzzy
        queries.push((
            Occur::Should,
            Box::new(BoostQuery::new(Box::new(title_fuzzy), 4.0)),
        ));
        queries.push((Occur::Should, Box::new(description_fuzzy)));
    });

    Ok(BooleanQuery::from(queries))
}

#[tracing::instrument(skip(index))]
fn build_filter_query(
    fields: &Fields,
    tantivy_query_syntax: &str,
    index: &tantivy::Index,
) -> AtomicResult<Box<dyn Query>> {
    let query_parser = QueryParser::for_index(index, vec![fields.propvals]);

    let query = query_parser
        .parse_query(tantivy_query_syntax)
        .map_err(|e| format!("Error parsing query: {}", e))?;

    Ok(query)
}

#[tracing::instrument(skip(store))]
fn build_parent_query(subject: &str, fields: &Fields, store: &Db) -> AtomicServerResult<TermQuery> {
    let resource = store.get_resource(subject)?;
    let facet = resource_to_facet(&resource, store)?;
    let term = Term::from_facet(fields.hierarchy, &facet);

    Ok(TermQuery::new(
        term,
        tantivy::schema::IndexRecordOption::Basic,
    ))
}

fn unpack_value(
    value: &tantivy::schema::Value,
    document: &tantivy::Document,
    name: String,
) -> Result<String, AtomicServerError> {
    match value {
        tantivy::schema::Value::Str(s) => Ok(s.to_string()),
        _else => Err(format!(
            "Search schema error: {} is not a string! Doc: {:?}",
            name, document
        )
        .into()),
    }
}

#[tracing::instrument(skip(searcher, docs))]
fn docs_to_subjects(
    docs: Vec<(f32, tantivy::DocAddress)>,
    fields: &Fields,
    searcher: &tantivy::Searcher,
) -> Result<Vec<String>, AtomicServerError> {
    let mut subjects: Vec<String> = Vec::new();

    // convert found documents to resources
    for (_score, doc_address) in docs {
        let retrieved_doc = searcher.doc(doc_address)?;
        let subject_val = retrieved_doc.get_first(fields.subject).ok_or("No 'subject' in search doc found. This is required when indexing. Run with --rebuild-index")?;

        let subject = unpack_value(subject_val, &retrieved_doc, "Subject".to_string())?;
        if !subjects.contains(&subject) {
            subjects.push(subject.clone());
        }
    }

    Ok(subjects.into_iter().collect())
}
