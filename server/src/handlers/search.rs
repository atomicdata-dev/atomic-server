use crate::{appstate::AppState, errors::BetterResult};
use actix_web::{web, HttpResponse};
use atomic_lib::{urls, Resource, Storelike};
use serde::Deserialize;
use std::{ops::RangeBounds, sync::Mutex};
use tantivy::{collector::TopDocs, query::QueryParser};

#[derive(Deserialize, Debug)]
pub struct SearchQuery {
    /// The actual search query
    pub q: String,
    /// Include the full resources in the response
    pub include: Option<bool>,
}

/// Parses a search query and responds with a list of resources
pub async fn search_query(
    data: web::Data<Mutex<AppState>>,
    query: web::Query<SearchQuery>,
    body: String,
    req: actix_web::HttpRequest,
) -> BetterResult<HttpResponse> {
    let context = data
        .lock()
        .expect("Failed to lock mutexguard in search_query");

    let store = &context.store;
    let searcher = context.search_reader.searcher();
    let fields = crate::search::get_schema_fields(&context);

    // construct the query
    let query_parser = QueryParser::for_index(
        &context.search_index,
        vec![
            fields.subject,
            // I don't think we need to search in the property
            // fields.property,
            fields.value,
        ],
    );
    let tantivy_query = query_parser
        .parse_query(&query.q)
        .map_err(|e| format!("Error parsing query {}", e))?;

    // execute the query
    let top_docs = searcher
        .search(&tantivy_query, &TopDocs::with_limit(10))
        .map_err(|e| "Error with creating docs for search")?;
    let mut subjects: Vec<String> = Vec::new();

    // convert found documents to resources
    for (_score, doc_address) in top_docs {
        let retrieved_doc = searcher.doc(doc_address).unwrap();
        let subject_val = retrieved_doc.get_first(fields.subject).unwrap();
        let subject = match subject_val {
            tantivy::schema::Value::Str(s) => s,
            _else => return Err("Subject is not a string!".into()),
        };
        if subjects.contains(subject) {
            continue;
        } else {
            subjects.push(subject.clone());
        }
    }
    let mut resources: Vec<Resource> = Vec::new();
    for s in subjects {
        resources.push(store.get_resource_extended(&s, true)?);
    }

    // You'd think there would be a simpler way of getting the requested URL...
    let subject = format!(
        "{}{}",
        store.get_self_url().ok_or("No base URL")?,
        req.uri()
            .path_and_query()
            .ok_or("Add a query param")?
            .to_string()
    );

    // Create a valid atomic data resource
    let mut results_resource = Resource::new(subject);
    results_resource.set_propval(urls::IS_A.into(), vec![urls::ENDPOINT].into(), store)?;
    results_resource.set_propval(urls::ENDPOINT_RESULTS.into(), resources.into(), store)?;
    results_resource.set_propval(
        urls::ENDPOINT_PARAMETERS.into(),
        vec![urls::SEARCH_QUERY].into(),
        store,
    )?;
    // let json_ad = atomic_lib::serialize::resources_to_json_ad(&resources)?;
    let mut builder = HttpResponse::Ok();
    // log::info!("Search q: {} hits: {}", &query.q, resources.len());
    Ok(builder.body(results_resource.to_json_ad()?))
}
