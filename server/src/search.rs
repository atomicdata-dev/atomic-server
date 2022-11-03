//! Full-text search, powered by Tantivy.
//! A folder for the index is stored in the config.
//! You can see the Endpoint on `http://localhost/search`
use atomic_lib::Db;
use atomic_lib::Resource;
use atomic_lib::Storelike;
use tantivy::schema::*;
use tantivy::Index;
use tantivy::IndexWriter;
use tantivy::ReloadPolicy;

use crate::config::Config;
use crate::errors::AtomicServerResult;

/// The actual Schema used for search.
/// It mimics a single Atom (or Triple).
#[derive(Debug)]
pub struct Fields {
    pub subject: Field,
    pub property: Field,
    pub value: Field,
    pub hierarchy: Field,
}

/// Contains the index and the schema. for search
#[derive(Clone)]
pub struct SearchState {
    /// reader for performing queries
    pub reader: tantivy::IndexReader,
    /// index
    pub index: tantivy::Index,
    /// For adding stuff to the search index
    /// Just take the read lock for adding documents, and the write lock for committing.
    // see https://github.com/quickwit-inc/tantivy/issues/550
    pub writer: std::sync::Arc<std::sync::RwLock<tantivy::IndexWriter>>,
    /// The shape of data stored in the index
    pub schema: tantivy::schema::Schema,
}

impl SearchState {
    /// Create a new SearchState for the Server, which includes building the schema and index.
    pub fn new(config: &Config) -> AtomicServerResult<SearchState> {
        let schema = crate::search::build_schema()?;
        let (writer, index) = crate::search::get_index(config)?;
        let reader = crate::search::get_reader(&index)?;
        let locked = std::sync::RwLock::from(writer);
        let arced = std::sync::Arc::from(locked);
        Ok(SearchState {
            schema,
            reader,
            index,
            writer: arced,
        })
    }
}

/// Returns the schema for the search index.
pub fn build_schema() -> AtomicServerResult<tantivy::schema::Schema> {
    let mut schema_builder = Schema::builder();
    // The STORED flag makes the index store the full values. Can be useful.
    schema_builder.add_text_field("subject", TEXT | STORED);
    schema_builder.add_text_field("property", TEXT | STORED);
    schema_builder.add_text_field("value", TEXT | STORED);
    schema_builder.add_facet_field("hierarchy", STORED);
    let schema = schema_builder.build();
    Ok(schema)
}

/// Creates or reads the index from the `search_index_path` and allocates some heap size.
pub fn get_index(config: &Config) -> AtomicServerResult<(IndexWriter, Index)> {
    let schema = build_schema()?;
    std::fs::create_dir_all(&config.search_index_path)?;
    if config.opts.rebuild_index {
        std::fs::remove_dir_all(&config.search_index_path)?;
        std::fs::create_dir_all(&config.search_index_path)?;
    }
    let mmap_directory = tantivy::directory::MmapDirectory::open(&config.search_index_path)?;
    let index = Index::open_or_create(mmap_directory, schema).map_err(|e| {
        format!(
            "Failed to create or open search index. Try starting again with --rebuild-index. Error: {}",
            e
        )
    })?;
    let heap_size_bytes = 50_000_000;
    let index_writer = index.writer(heap_size_bytes)?;
    Ok((index_writer, index))
}

/// Returns the schema for the search index.
pub fn get_schema_fields(appstate: &SearchState) -> AtomicServerResult<Fields> {
    let subject = appstate
        .schema
        .get_field("subject")
        .ok_or("No 'subject' in the schema")?;
    let property = appstate
        .schema
        .get_field("property")
        .ok_or("No 'property' in the schema")?;
    let value = appstate
        .schema
        .get_field("value")
        .ok_or("No 'value' in the schema")?;
    let hierarchy = appstate
        .schema
        .get_field("hierarchy")
        .ok_or("No 'hierarchy' in the schema")?;

    Ok(Fields {
        subject,
        property,
        value,
        hierarchy,
    })
}

/// Indexes all resources from the store to search.
/// At this moment does not remove existing index.
pub fn add_all_resources(search_state: &SearchState, store: &Db) -> AtomicServerResult<()> {
    let resources = store
        .all_resources(true)
        .filter(|resource| !resource.get_subject().contains("/commits/"));

    for resource in resources {
        add_resource(search_state, &resource, store)?;
    }

    search_state.writer.write()?.commit()?;
    Ok(())
}

/// Adds a single resource to the search index, but does _not_ commit!
/// Does not index outgoing links, or resourcesArrays
/// `appstate.search_index_writer.write()?.commit()?;`
#[tracing::instrument(skip(appstate, store))]
pub fn add_resource(
    appstate: &SearchState,
    resource: &Resource,
    store: &Db,
) -> AtomicServerResult<()> {
    let fields = get_schema_fields(appstate)?;
    let subject = resource.get_subject();
    let writer = appstate.writer.read()?;
    let hierarchy = resource_to_facet(resource, store)?;

    for (prop, val) in resource.get_propvals() {
        match val {
            atomic_lib::Value::AtomicUrl(_) | atomic_lib::Value::ResourceArray(_) => continue,
            _ => {
                add_triple(
                    &writer,
                    subject.into(),
                    prop.into(),
                    val.to_string(),
                    Some(hierarchy.clone()),
                    &fields,
                )?;
            }
        };
    }
    Ok(())
}

/// Removes a single resource from the search index, but does _not_ commit!
/// Does not index outgoing links, or resourcesArrays
/// `appstate.search_index_writer.write()?.commit()?;`
#[tracing::instrument(skip(search_state))]
pub fn remove_resource(search_state: &SearchState, subject: &str) -> AtomicServerResult<()> {
    let fields = get_schema_fields(search_state)?;
    let writer = search_state.writer.read()?;
    let term = tantivy::Term::from_field_text(fields.subject, subject);
    writer.delete_term(term);
    Ok(())
}

/// Adds a single atom or triple to the search index, but does _not_ commit!
/// `appstate.search_index_writer.write()?.commit()?;`
#[tracing::instrument(skip(writer, fields))]
pub fn add_triple(
    writer: &IndexWriter,
    subject: String,
    property: String,
    value: String,
    hierarchy: Option<Facet>,
    fields: &Fields,
) -> AtomicServerResult<()> {
    let mut doc = Document::default();
    doc.add_text(fields.property, property);
    doc.add_text(fields.value, value);
    doc.add_text(fields.subject, subject);

    if let Some(hierarchy) = hierarchy {
        doc.add_facet(fields.hierarchy, hierarchy);
    }

    writer.add_document(doc)?;
    Ok(())
}

// For a search server you will typically create one reader for the entire lifetime of your program, and acquire a new searcher for every single request.
pub fn get_reader(index: &tantivy::Index) -> AtomicServerResult<tantivy::IndexReader> {
    Ok(index
        .reader_builder()
        .reload_policy(ReloadPolicy::OnCommit)
        .try_into()?)
}

pub fn subject_to_facet(subject: String) -> AtomicServerResult<Facet> {
    Facet::from_encoded(subject.into_bytes())
        .map_err(|e| format!("Failed to create facet from subject. Error: {}", e).into())
}

pub fn resource_to_facet(resource: &Resource, store: &Db) -> AtomicServerResult<Facet> {
    let mut parent_tree = resource.get_parent_tree(store)?;
    parent_tree.reverse();

    let mut hierarchy_bytes: Vec<u8> = Vec::new();

    for (index, parent) in parent_tree.iter().enumerate() {
        let facet = subject_to_facet(parent.get_subject().to_string())?;

        if index != 0 {
            hierarchy_bytes.push(0u8);
        }

        hierarchy_bytes.append(&mut facet.encoded_str().to_string().into_bytes());
    }
    let leaf_facet = subject_to_facet(resource.get_subject().to_string())?;

    if !hierarchy_bytes.is_empty() {
        hierarchy_bytes.push(0u8);
    }

    hierarchy_bytes.append(&mut leaf_facet.encoded_str().to_string().into_bytes());

    let result = Facet::from_encoded(hierarchy_bytes)
        .map_err(|e| format!("Failed to convert resource to facet, Error: {}", e))
        .unwrap();

    Ok(result)
}

#[cfg(test)]
mod tests {
    use atomic_lib::{urls, Resource, Storelike};

    use super::resource_to_facet;
    #[test]
    fn facet_contains_subfacet() {
        let store = atomic_lib::Db::init_temp("facet_contains").unwrap();
        let mut prev_subject: Option<String> = None;
        let mut resources = Vec::new();

        for index in [0, 1, 2].iter() {
            let subject = format!("http://example.com/{}", index);

            let mut resource = Resource::new(subject.clone());
            if let Some(prev_subject) = prev_subject.clone() {
                resource
                    .set_propval_string(urls::PARENT.into(), &prev_subject, &store)
                    .unwrap();
            }

            prev_subject = Some(subject.clone());

            store.add_resource(&resource).unwrap();
            resources.push(resource);
        }

        let parent_tree = resources[2].get_parent_tree(&store).unwrap();
        assert_eq!(parent_tree.len(), 2);

        let index_facet = resource_to_facet(&resources[2], &store).unwrap();

        let query_facet_direct_parent = resource_to_facet(&resources[1], &store).unwrap();
        let query_facet_root = resource_to_facet(&resources[0], &store).unwrap();

        // println!("Index: {:?}", index_facet);
        // println!("query direct: {:?}", query_facet_direct_parent);
        // println!("query root: {:?}", query_facet_root);

        assert!(query_facet_direct_parent.is_prefix_of(&index_facet));
        assert!(query_facet_root.is_prefix_of(&index_facet));
    }
}
