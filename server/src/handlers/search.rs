//! Full-text search is achieved with the Tantivy crate.
//! The index is built whenever --rebuild-index is passed,
//! or after a commit is processed by the CommitMonitor.
//! Tantivy requires a strict schema, whereas Atomic is dynamic.
//! We deal with this discrepency by

use crate::{appstate::AppState, errors::AtomicServerResult};
use actix_web::{web, HttpResponse};
use atomic_lib::{urls, Resource, Storelike};
use serde::Deserialize;
use tantivy::{collector::TopDocs, query::QueryParser};

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

    let mut should_fuzzy = true;
    if params.property.is_some() {
        // Fuzzy searching is not possible when filtering by property
        should_fuzzy = false;
    }

    let mut subjects: Vec<String> = Vec::new();
    // These are not used at this moment, but would be quite useful in RDF context.
    let mut atoms: Vec<StringAtom> = Vec::new();

    if let Some(q) = params.q.clone() {
        // If any of these substrings appear, the user wants an exact / advanced search
        let dont_fuzz_strings = vec!["*", "AND", "OR", "[", "\"", ":", "+", "-", " "];
        for dont_fuzz in dont_fuzz_strings {
            if q.contains(dont_fuzz) {
                should_fuzzy = false
            }
        }

        let query: Box<dyn tantivy::query::Query> = if should_fuzzy {
            let term = tantivy::Term::from_field_text(fields.value, &q);
            let query = tantivy::query::FuzzyTermQuery::new_prefix(term, 1, true);
            Box::new(query)
        } else {
            // construct the query
            let query_parser = QueryParser::for_index(
                &appstate.search_state.index,
                vec![
                    fields.subject,
                    // I don't think we need to search in the property
                    // fields.property,
                    fields.value,
                ],
            );
            let full_query = if let Some(prop) = &params.property {
                format!("property:{:?} AND {}", prop, &q)
            } else {
                q
            };
            let tantivy_query = query_parser
                .parse_query(&full_query)
                .map_err(|e| format!("Error parsing query {}", e))?;
            tantivy_query
        };

        // With this first limit, we go for a greater number - as the user may not have the rights to the first ones!
        // We filter these results later.
        // https://github.com/joepio/atomic-data-rust/issues/279.
        let initial_results_limit = 100;

        // execute the query
        let top_docs = searcher
            .search(&query, &TopDocs::with_limit(initial_results_limit))
            .map_err(|e| format!("Error with creating search results: {} ", e))?;

        // convert found documents to resources
        for (_score, doc_address) in top_docs {
            let retrieved_doc = searcher.doc(doc_address)?;
            let subject_val = retrieved_doc.get_first(fields.subject).ok_or("No 'subject' in search doc found. This is required when indexing. Run with --rebuild-index")?;
            let prop_val = retrieved_doc.get_first(fields.property).ok_or("No 'property' in search doc found. This is required when indexing. Run with --rebuild-index")?;
            let value_val = retrieved_doc.get_first(fields.value).ok_or("No 'value' in search doc found. This is required when indexing. Run with --rebuild-index")?;
            let subject = match subject_val {
                tantivy::schema::Value::Str(s) => s.to_string(),
                _else => {
                    return Err(format!(
                        "Search schema error: Subject is not a string! Doc: {:?}",
                        retrieved_doc
                    )
                    .into())
                }
            };
            let property = match prop_val {
                tantivy::schema::Value::Str(s) => s.to_string(),
                _else => {
                    return Err(format!(
                        "Search schema error: Property is not a string! Doc: {:?}",
                        retrieved_doc
                    )
                    .into())
                }
            };
            let value = match value_val {
                tantivy::schema::Value::Str(s) => s.to_string(),
                _else => {
                    return Err(format!(
                        "Search schema error: Value is not a string! Doc: {:?}",
                        retrieved_doc
                    )
                    .into())
                }
            };
            if subjects.contains(&subject) {
                continue;
            } else {
                subjects.push(subject.clone());
                let atom = StringAtom {
                    subject,
                    property,
                    value,
                };
                atoms.push(atom);
            }
        }
    }

    // Create a valid atomic data resource.
    // You'd think there would be a simpler way of getting the requested URL...
    let subject = format!(
        "{}{}",
        store.get_self_url().ok_or("No base URL set")?,
        req.uri().path_and_query().ok_or("Add a query param")?
    );

    let mut results_resource = atomic_lib::plugins::search::search_endpoint().to_resource(store)?;
    results_resource.set_subject(subject.clone());

    if appstate.config.opts.rdf_search {
        // Always return all subjects in `--rdf-search` mode, don't do authentication
        results_resource.set_propval(urls::ENDPOINT_RESULTS.into(), subjects.into(), store)?;
    } else {
        // Default case: return full resources, do authentication
        let mut resources: Vec<Resource> = Vec::new();

        // This is a pretty expensive operation. We need to check the rights for the subjects to prevent data leaks.
        // But we could probably do some things to speed this up: make it async / parallel, check admin rights.
        // https://github.com/joepio/atomic-data-rust/issues/279
        // https://github.com/joepio/atomic-data-rust/issues/280
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
                    tracing::info!("Skipping search result: {} : {}", s, _e);
                    continue;
                }
            }
        }
        results_resource.set_propval(urls::ENDPOINT_RESULTS.into(), resources.into(), store)?;
    }
    let mut builder = HttpResponse::Ok();
    // TODO: support other serialization options
    Ok(builder.body(results_resource.to_json_ad()?))
}

/// Posts an N-Triples RDF document to index the triples in search
#[tracing::instrument(skip(appstate))]
pub async fn search_index_rdf(
    appstate: web::Data<AppState>,
    body: String,
) -> AtomicServerResult<HttpResponse> {
    // Parse Turtle
    use rio_api::parser::TriplesParser;
    use rio_turtle::{TurtleError, TurtleParser};

    let mut writer = appstate.search_state.writer.write()?;
    let fields = crate::search::get_schema_fields(&appstate.search_state)?;

    TurtleParser::new(body.as_ref(), None)
        .parse_all(&mut |t| {
            match (
                get_inner_value(t.subject.into()),
                get_inner_value(t.predicate.into()),
                get_inner_value(t.object),
            ) {
                (Some(s), Some(p), Some(o)) => {
                    crate::search::add_triple(&writer, s, p, o, &fields).ok();
                }
                _ => return Ok(()),
            };
            Ok(()) as Result<(), TurtleError>
        })
        .map_err(|e| format!("Error parsing turtle: {}", e))?;

    // Store the changes to the writer
    writer.commit()?;
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
        Term::BlankNode(_bn) => None,
        Term::Triple(_) => None,
    }
}

#[derive(Debug)]
pub struct StringAtom {
    pub subject: String,
    pub property: String,
    pub value: String,
}
