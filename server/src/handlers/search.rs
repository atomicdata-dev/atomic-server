use crate::{appstate::AppState, errors::BetterResult};
use actix_web::{web, HttpResponse};
use atomic_lib::{urls, Resource, Storelike};
use serde::Deserialize;
use std::sync::Mutex;
use tantivy::{collector::TopDocs, query::QueryParser};

#[derive(Deserialize, Debug)]
pub struct SearchQuery {
    /// The actual search query
    pub q: String,
    /// Include the full resources in the response
    pub subjects: Option<bool>,
}

/// Parses a search query and responds with a list of resources
pub async fn search_query(
    data: web::Data<Mutex<AppState>>,
    params: web::Query<SearchQuery>,
    req: actix_web::HttpRequest,
) -> BetterResult<HttpResponse> {
    let context = data
        .lock()
        .expect("Failed to lock mutexguard in search_query");

    let store = &context.store;
    let searcher = context.search_reader.searcher();
    let fields = crate::search::get_schema_fields(&context);

    let mut should_fuzzy = true;
    let return_subjects = params.subjects.unwrap_or(false);
    let query = params.q.clone();
    // If any of these substrings appear, the user wants an exact / advanced search
    let dont_fuzz_strings = vec!["*", "AND", "OR", "[", "\""];
    for dont_fuzz in dont_fuzz_strings {
        if query.contains(dont_fuzz) {
            should_fuzzy = false
        }
    }

    let query: Box<dyn tantivy::query::Query> = if should_fuzzy {
        let term = tantivy::Term::from_field_text(fields.value, &params.q);
        let query = tantivy::query::FuzzyTermQuery::new_prefix(term, 2, true);
        Box::new(query)
    } else {
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
            .parse_query(&params.q)
            .map_err(|e| format!("Error parsing query {}", e))?;
        tantivy_query
    };

    // execute the query
    let top_docs = searcher
        .search(&query, &TopDocs::with_limit(10))
        .map_err(|e| format!("Error with creating search results: {} ", e))?;
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

    // Create a valid atomic data resource.
    // You'd think there would be a simpler way of getting the requested URL...
    let subject = format!(
        "{}{}",
        store.get_self_url().ok_or("No base URL set")?,
        req.uri()
            .path_and_query()
            .ok_or("Add a query param")?
            .to_string()
    );
    let mut results_resource = Resource::new(subject);
    results_resource.set_propval(urls::IS_A.into(), vec![urls::ENDPOINT].into(), store)?;
    results_resource.set_propval(urls::DESCRIPTION.into(), atomic_lib::Value::Markdown("Full text-search endpoint. You can use the keyword `AND` and `OR`, or use `\"` for advanced searches. ".into()), store)?;
    results_resource.set_propval(
        urls::ENDPOINT_PARAMETERS.into(),
        vec![urls::SEARCH_QUERY].into(),
        store,
    )?;

    if return_subjects {
        results_resource.set_propval(urls::ENDPOINT_RESULTS.into(), subjects.into(), store)?;
    } else {
        let mut resources: Vec<Resource> = Vec::new();
        for s in subjects {
            // If triples isn't set, return
            resources.push(store.get_resource_extended(&s, true).map_err(|e| format!("Failed to construct search results, because one of the Subjects cannot be returned. Try again with the `&subjects=true` query parameter. Error: {}", e))?);
        }
        results_resource.set_propval(urls::ENDPOINT_RESULTS.into(), resources.into(), store)?;
    }

    // let json_ad = atomic_lib::serialize::resources_to_json_ad(&resources)?;
    let mut builder = HttpResponse::Ok();
    // log::info!("Search q: {} hits: {}", &query.q, resources.len());
    Ok(builder.body(results_resource.to_json_ad()?))
}

/// Posts an N-Triples RDF document to index the triples in search
pub async fn search_index(
    data: web::Data<Mutex<AppState>>,
    body: String,
) -> BetterResult<HttpResponse> {
    let appstate = data
        .lock()
        .expect("Failed to lock mutexguard in search_query");

    // Parse Turtle
    use rio_api::parser::TriplesParser;
    use rio_turtle::{TurtleError, TurtleParser};

    let mut writer = appstate.search_index_writer.write()?;
    let fields = crate::search::get_schema_fields(&appstate);

    TurtleParser::new(body.as_ref(), None)
        .parse_all(&mut |t| {
            match (
                get_inner_value(t.subject.into()),
                get_inner_value(t.predicate.into()),
                get_inner_value(t.object),
            ) {
                (Some(s), Some(p), Some(o)) => {
                    println!("adding {} {} {}", s, p, o);
                    crate::search::add_triple(&writer, s, p, o, &fields).unwrap();
                }
                _ => return Ok(()),
            };
            Ok(()) as Result<(), TurtleError>
        })
        .map_err(|e| format!("Error parsing turtle: {}", e))?;

    // Store the changes to the writer
    writer.commit().unwrap();
    let mut builder = HttpResponse::Ok();
    Ok(builder.body("Added turtle to store"))
}

// Returns the innver value of a Term in an RDF triple. If it's a blanknode or triple inside a triple, it will return None.
use rio_api::model::Term;
fn get_inner_value(t: Term) -> Option<String> {
    match t {
        Term::Literal(lit) => match lit {
            rio_api::model::Literal::Simple { value } => Some(value.into()),
            rio_api::model::Literal::LanguageTaggedString { value, language: _ } => {
                Some(value.into())
            }
            rio_api::model::Literal::Typed { value, datatype: _ } => Some(value.into()),
        },
        Term::NamedNode(nn) => Some(nn.iri.into()),
        Term::BlankNode(bn) => None,
        Term::Triple(_) => None,
    }
}