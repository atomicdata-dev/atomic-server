//! Full-text search, powered by Tantivy.
//! A folder for the index is stored in the config.
//! You can see the Endpoint on `http://localhost/search`

use atomic_lib::Resource;
use atomic_lib::Storelike;
use tantivy::schema::*;
use tantivy::Index;
use tantivy::IndexWriter;
use tantivy::ReloadPolicy;

use crate::appstate::AppState;
use crate::config::Config;
use crate::errors::BetterResult;

/// The actual Schema used for search.
/// It mimics a single Atom (or Triple).
pub struct Fields {
    pub subject: Field,
    pub property: Field,
    pub value: Field,
}

/// Returns the schema for the search index.
pub fn build_schema() -> BetterResult<tantivy::schema::Schema> {
    let mut schema_builder = Schema::builder();
    // The STORED flag makes the index store the full values. Can be useful.
    schema_builder.add_text_field("subject", TEXT | STORED);
    schema_builder.add_text_field("property", TEXT | STORED);
    schema_builder.add_text_field("value", TEXT | STORED);
    let schema = schema_builder.build();
    Ok(schema)
}

/// Creates or reads the index from the `search_index_path` and allocates some heap size.
pub fn get_index(config: &Config) -> BetterResult<(IndexWriter, Index)> {
    let schema = build_schema()?;
    std::fs::create_dir_all(&config.search_index_path).unwrap();
    let mmap_directory =
        tantivy::directory::MmapDirectory::open(&config.search_index_path).unwrap();

    let index = Index::open_or_create(mmap_directory, schema).unwrap();
    let heap_size_bytes = 50_000_000;
    let index_writer = index.writer(heap_size_bytes).unwrap();
    Ok((index_writer, index))
}

/// Returns the schema for the search index.
pub fn get_schema_fields(appstate: &AppState) -> Fields {
    let subject = appstate.search_schema.get_field("subject").unwrap();
    let property = appstate.search_schema.get_field("property").unwrap();
    let value = appstate.search_schema.get_field("value").unwrap();

    Fields {
        subject,
        property,
        value,
    }
}

/// Indexes all resources from the store to search.
/// At this moment does not remove existing index.
pub fn add_all_resources(appstate: &AppState) -> BetterResult<()> {
    log::info!("Building search index...");
    for resource in appstate.store.all_resources(true) {
        add_resource(appstate, &resource)?;
    }
    appstate.search_index_writer.write()?.commit().unwrap();
    log::info!("Finished building search index!");
    Ok(())
}

/// Adds a single resource to the search index, but does _not_ commit!
/// `appstate.search_index_writer.write()?.commit().unwrap();`
pub fn add_resource(appstate: &AppState, resource: &Resource) -> BetterResult<()> {
    let fields = get_schema_fields(appstate);
    let subject = resource.get_subject();
    for (prop, val) in resource.get_propvals() {
        let mut doc = Document::default();
        doc.add_text(fields.property, prop);
        doc.add_text(fields.value, &val.to_string());
        doc.add_text(fields.subject, subject);
        appstate.search_index_writer.read()?.add_document(doc);
    }
    Ok(())
}

// For a search server you will typically create one reader for the entire lifetime of your program, and acquire a new searcher for every single request.
pub fn get_reader(index: &tantivy::Index) -> BetterResult<tantivy::IndexReader> {
    Ok(index
        .reader_builder()
        .reload_policy(ReloadPolicy::OnCommit)
        .try_into()
        .map_err(|_e| "Failed getting search reader")
        .unwrap())
}
