use atomic_lib::Resource;
/// Full-text search, powered by Tantivy.
use tantivy::collector::TopDocs;
use tantivy::query::QueryParser;
use tantivy::schema::*;
use tantivy::Index;
use tantivy::IndexWriter;
use tantivy::ReloadPolicy;

use crate::appstate::AppState;
use crate::config::Config;
use crate::errors::BetterResult;

/// Returns the schema for the search index.
pub fn build_schema() -> BetterResult<tantivy::schema::Schema> {
    let mut schema_builder = Schema::builder();
    // The STORED flag makes the index store the full values. Can be useful.
    schema_builder.add_text_field("property", TEXT | STORED);
    schema_builder.add_text_field("value", TEXT);
    let schema = schema_builder.build();
    Ok(schema)
}

pub fn get_index(config: &Config) -> BetterResult<(IndexWriter, Index)> {
    let schema = build_schema()?;
    let index = Index::create_in_dir(&config.search_index_path, schema).unwrap();
    let heap_size_bytes = 50_000_000;
    let mut index_writer = index.writer(heap_size_bytes).unwrap();
    Ok((index_writer, index))
}

pub fn get_schema_fields(appstate: &AppState) -> (Field, Field) {
    let property_field = appstate.search_schema.get_field("property").unwrap();
    let value_field = appstate.search_schema.get_field("value").unwrap();
    (property_field, value_field)
}

fn add_resource(appstate: AppState, resource: &Resource) -> BetterResult<()> {
    let mut doc = Document::default();
    let property_field = appstate.search_schema.get_field("property").unwrap();
    let value_field = appstate.search_schema.get_field("value").unwrap();
    for (prop, val) in resource.get_propvals() {
        doc.add_text(property_field, prop);
        doc.add_text(value_field, &val.to_string());
    }
    appstate.search_index_writer.read()?.add_document(doc);
    // TODO: don't do this every time!
    appstate.search_index_writer.write()?.commit().unwrap();
    Ok(())
}

// For a search server you will typically create one reader for the entire lifetime of your program, and acquire a new searcher for every single request.
pub fn get_reader(index: &tantivy::Index) -> BetterResult<tantivy::IndexReader> {
    Ok(index
        .reader_builder()
        .reload_policy(ReloadPolicy::OnCommit)
        .try_into()
        .map_err(|e| "Failed getting reader")
        .unwrap())
}
