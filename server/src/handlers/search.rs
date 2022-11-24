//! Full-text search is achieved with the Tantivy crate.
//! The index is built whenever --rebuild-index is passed,
//! or after a commit is processed by the CommitMonitor.
//! Tantivy requires a strict schema, whereas Atomic is dynamic.
//! We deal with this discrepency by

use std::collections::HashSet;

use crate::{
    appstate::AppState,
    errors::{AtomicServerError, AtomicServerResult},
    search::{resource_to_facet, Fields},
};
use actix_web::{web, HttpResponse};
use atomic_lib::{errors::AtomicResult, urls, Db, Resource, Storelike};
use serde::Deserialize;
use tantivy::{
    collector::TopDocs,
    query::{BooleanQuery, BoostQuery, QueryParser},
};

type Queries = Vec<(tantivy::query::Occur, Box<dyn tantivy::query::Query>)>;

#[derive(Deserialize, Debug)]
pub struct SearchQuery {
    /// The actual search query
    pub q: Option<String>,
    /// Include the full resources in the response
    pub include: Option<bool>,
    /// Maximum amount of results
    pub limit: Option<usize>,
    /// Filter by Property URL
    pub property: Option<String>,
    /// Only include resources that have this resource as its ancestor
    pub parent: Option<String>,
    /// Filter based on props
    pub filter: Option<String>,
}

/// Parses a search query and responds with a list of resources
#[tracing::instrument(skip(appstate, req))]
pub async fn search_query(
    appstate: web::Data<AppState>,
    params: web::Query<SearchQuery>,
    req: actix_web::HttpRequest,
) -> AtomicServerResult<HttpResponse> {
    let store = &appstate.store;
    let searcher = appstate.search_state.reader.searcher();
    let fields = crate::search::get_schema_fields(&appstate.search_state)?;
    let default_limit = 30;
    let limit = if let Some(l) = params.limit {
        if l > 0 {
            l
        } else {
            default_limit
        }
    } else {
        default_limit
    };

    // With this first limit, we go for a greater number - as the user may not have the rights to the first ones!
    // We filter these results later.
    // https://github.com/atomicdata-dev/atomic-data-rust/issues/279.
    let initial_results_limit = 100;

    let mut query_list: Queries = Vec::new();

    if let Some(parent) = params.parent.clone() {
        let query = build_parent_query(parent, &fields, store)?;

        query_list.push((tantivy::query::Occur::Must, Box::new(query)));
    }

    if let Some(q) = params.q.clone() {
        let fuzzy_query = build_fuzzy_query(&fields, &q);

        query_list.push((tantivy::query::Occur::Must, Box::new(fuzzy_query)));
    }

    if let Some(filter) = params.filter.clone() {
        let exact_query = BoostQuery::new(
            build_query(&fields, &filter, &appstate.search_state.index)?,
            20.0,
        );

        query_list.push((tantivy::query::Occur::Must, Box::new(exact_query)));
    }

    let query = BooleanQuery::new(query_list);

    // execute the query
    let top_docs = searcher
        .search(&query, &TopDocs::with_limit(initial_results_limit))
        .map_err(|e| format!("Error with creating search results: {} ", e))?;

    let subjects = docs_to_resources(top_docs, &fields, &searcher)?;

    // Create a valid atomic data resource.
    // You'd think there would be a simpler way of getting the requested URL...
    let subject = format!(
        "{}{}",
        store.get_self_url().ok_or("No base URL set")?,
        req.uri().path_and_query().ok_or("Add a query param")?
    );

    let mut results_resource = atomic_lib::plugins::search::search_endpoint().to_resource(store)?;
    results_resource.set_subject(subject.clone());

    // Default case: return full resources, do authentication
    let mut resources: Vec<Resource> = Vec::new();

    // This is a pretty expensive operation. We need to check the rights for the subjects to prevent data leaks.
    // But we could probably do some things to speed this up: make it async / parallel, check admin rights.
    // https://github.com/atomicdata-dev/atomic-data-rust/issues/279
    // https://github.com/atomicdata-dev/atomic-data-rust/issues/280
    let for_agent = crate::helpers::get_client_agent(req.headers(), &appstate, subject)?;
    for s in subjects {
        match store.get_resource_extended(&s, true, for_agent.as_deref()) {
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
    results_resource.set_propval(urls::ENDPOINT_RESULTS.into(), resources.into(), store)?;

    let mut builder = HttpResponse::Ok();
    // TODO: support other serialization options
    Ok(builder.body(results_resource.to_json_ad()?))
}

#[derive(Debug, std::hash::Hash, Eq, PartialEq)]
pub struct StringAtom {
    pub subject: String,
    pub property: String,
    pub value: String,
}

fn build_fuzzy_query(fields: &Fields, q: &str) -> impl tantivy::query::Query {
    let title_term = tantivy::Term::from_field_text(fields.title, q);
    let description_term = tantivy::Term::from_field_text(fields.description, q);
    let title_query = tantivy::query::FuzzyTermQuery::new_prefix(title_term, 1, true);
    let description_query = tantivy::query::FuzzyTermQuery::new_prefix(description_term, 1, true);

    let queries: Queries = vec![
        (
            tantivy::query::Occur::Should,
            Box::new(BoostQuery::new(Box::new(title_query), 2.0)),
        ),
        (tantivy::query::Occur::Should, Box::new(description_query)),
    ];

    BooleanQuery::from(queries)
}

#[tracing::instrument(skip(index))]
fn build_query(
    fields: &Fields,
    q: &str,
    index: &tantivy::Index,
) -> AtomicResult<Box<dyn tantivy::query::Query>> {
    // construct the query
    let query_parser = QueryParser::for_index(index, vec![fields.propvals]);

    let query_text = q.to_string();

    let query = query_parser
        .parse_query(&query_text)
        .map_err(|e| format!("Error parsing query {}", e))?;

    Ok(query)
}

#[tracing::instrument(skip(store))]
fn build_parent_query(
    subject: String,
    fields: &Fields,
    store: &Db,
) -> AtomicServerResult<tantivy::query::TermQuery> {
    let resource = store.get_resource(subject.as_str())?;
    let facet = resource_to_facet(&resource, store)?;

    let term = tantivy::Term::from_facet(fields.hierarchy, &facet);

    Ok(tantivy::query::TermQuery::new(
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
fn docs_to_resources(
    docs: Vec<(f32, tantivy::DocAddress)>,
    fields: &Fields,
    searcher: &tantivy::LeasedItem<tantivy::Searcher>,
) -> Result<Vec<String>, AtomicServerError> {
    let mut subjects: HashSet<String> = HashSet::new();

    // convert found documents to resources
    for (_score, doc_address) in docs {
        let retrieved_doc = searcher.doc(doc_address)?;
        let subject_val = retrieved_doc.get_first(fields.subject).ok_or("No 'subject' in search doc found. This is required when indexing. Run with --rebuild-index")?;

        let subject = unpack_value(subject_val, &retrieved_doc, "Subject".to_string())?;

        subjects.insert(subject.clone());
    }

    Ok(subjects.into_iter().collect())
}
