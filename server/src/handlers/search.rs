use crate::{appstate::AppState, errors::BetterResult};
use actix_web::{web, HttpResponse};
use serde::Deserialize;
use std::sync::Mutex;
use tantivy::{collector::TopDocs, query::QueryParser};

#[derive(Deserialize, Debug)]
pub struct SearchQuery {
    /// The actual search query
    pub query: String,
}

/// Parses a search query and responds with a list of resources
pub async fn search_query(
    data: web::Data<Mutex<AppState>>,
    query: web::Query<SearchQuery>,
    body: String,
) -> BetterResult<HttpResponse> {
    let mut context = data
        .lock()
        .expect("Failed to lock mutexguard in search_query");

    let store = &mut context.store;
    let searcher = context.search_reader.searcher();
    let (property_field, value_field) = crate::search::get_schema_fields(&context);
    let query_parser =
        QueryParser::for_index(&context.search_index, vec![property_field, value_field]);
    let tantivy_query = query_parser
        .parse_query(&query.query)
        .map_err(|e| format!("Error parsing query {}", e))?;
    let top_docs = searcher
        .search(&tantivy_query, &TopDocs::with_limit(10))
        .map_err(|e| "Error with creating docs for search")?;
    for (_score, doc_address) in top_docs {
        let retrieved_doc = searcher.doc(doc_address).unwrap();
        println!("{}", context.search_schema.to_json(&retrieved_doc));
    }
    let mut builder = HttpResponse::Ok();
    let message = format!("succesful search for {:?}", query.query);
    log::info!("{}", &message);
    Ok(builder.body(message))
}
