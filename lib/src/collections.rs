//! Collections are dynamic resources that refer to multiple resources.
//! They are constructed using a [Query]
use crate::{
    agents::ForAgent, errors::AtomicResult, storelike::ResourceCollection, urls, Query, Resource,
    Storelike, Value,
};

const DEFAULT_PAGE_SIZE: usize = 30;

/// Used to construct a Collection. Does not contain results / members.
/// Has to be constructed using `Collection::new()` or `storelike.new_collection()`.
#[derive(Debug)]
pub struct CollectionBuilder {
    /// Full Subject URL of the resource, including query parameters
    pub subject: String,
    /// The property which the results are to be filtered by
    pub property: Option<String>,
    /// The value which the results are to be filtered by
    pub value: Option<String>,
    /// URL of the value to sort by
    pub sort_by: Option<String>,
    /// Sorts ascending by default
    pub sort_desc: bool,
    /// Current page number, defaults to 0 (first page)
    pub current_page: usize,
    /// How many items per page
    pub page_size: usize,
    /// A human readable name
    pub name: Option<String>,
    /// Whether it's children should be included as nested resources in the response
    pub include_nested: bool,
    /// Whether to include resources from other servers
    pub include_external: bool,
}

impl CollectionBuilder {
    /// Converts a CollectionBuilder into a Resource.
    /// Note that this does not calculate any members, and it does not generate any pages.
    /// If that is what you need, use `.into_resource`
    pub fn to_resource(&self, store: &impl Storelike) -> AtomicResult<crate::Resource> {
        let mut resource = store.get_resource_new(&self.subject);
        resource.set_class(urls::COLLECTION);
        if let Some(val) = &self.property {
            resource.set_propval_string(crate::urls::COLLECTION_PROPERTY.into(), val, store)?;
        }
        if let Some(val) = &self.value {
            resource.set_propval_string(crate::urls::COLLECTION_VALUE.into(), val, store)?;
        }
        if let Some(val) = &self.name {
            resource.set_propval_string(crate::urls::NAME.into(), val, store)?;
        }
        if let Some(val) = &self.sort_by {
            resource.set_propval_string(crate::urls::COLLECTION_SORT_BY.into(), val, store)?;
        }
        if self.include_nested {
            resource.set_propval_string(
                crate::urls::COLLECTION_INCLUDE_NESTED.into(),
                "true",
                store,
            )?;
        }
        if self.include_external {
            resource.set_propval_string(
                crate::urls::COLLECTION_INCLUDE_EXTERNAL.into(),
                "true",
                store,
            )?;
        }
        if self.sort_desc {
            resource.set_propval_string(crate::urls::COLLECTION_SORT_DESC.into(), "true", store)?;
        }
        resource.set_propval_string(
            crate::urls::COLLECTION_CURRENT_PAGE.into(),
            &self.current_page.to_string(),
            store,
        )?;
        resource.set_propval(
            crate::urls::COLLECTION_PAGE_SIZE.into(),
            self.page_size.into(),
            store,
        )?;
        // Maybe include items directly
        Ok(resource)
    }

    /// Default CollectionBuilder for Classes. Finds all resources by class URL. Has sensible defaults.
    pub fn class_collection(
        class_url: &str,
        path: &str,
        store: &impl Storelike,
    ) -> CollectionBuilder {
        CollectionBuilder {
            subject: store.get_server_url().clone().set_path(path).to_string(),
            property: Some(urls::IS_A.into()),
            value: Some(class_url.into()),
            sort_by: None,
            sort_desc: false,
            page_size: DEFAULT_PAGE_SIZE,
            current_page: 0,
            name: Some(format!("{} collection", path)),
            include_nested: true,
            include_external: false,
        }
    }

    /// Converts the CollectionBuilder into a collection, with Members
    pub fn into_collection(
        self,
        store: &impl Storelike,
        for_agent: &ForAgent,
    ) -> AtomicResult<Collection> {
        Collection::collect_members(store, self, for_agent)
    }
}

/// Dynamic resource used for ordering, filtering and querying content.
/// Contains members / results. Use CollectionBuilder if you don't (yet) need the results.
/// Features pagination.
#[derive(Debug)]
pub struct Collection {
    /// Full Subject URL of the resource, including query parameters
    pub subject: String,
    /// The property which the results are to be filtered by
    pub property: Option<String>,
    /// The value which the results are to be filtered by
    pub value: Option<String>,
    /// The actual items that you're interested in. List the member subjects of the current page.
    pub members: Vec<String>,
    /// The members as full resources, instead of a list of subjects. Is only populated if `nested` is true.
    pub members_nested: Option<Vec<Resource>>,
    /// URL of the value to sort by
    pub sort_by: Option<String>,
    // Sorts ascending by default
    pub sort_desc: bool,
    /// How many items per page
    pub page_size: usize,
    /// Current page number, defaults to 0 (first page)
    pub current_page: usize,
    /// Total number of items
    pub total_items: usize,
    /// Total number of pages
    pub total_pages: usize,
    /// Human readable name of a resource
    pub name: Option<String>,
    /// Whether it's children should be included as nested resources in the response
    pub include_nested: bool,
    /// Include resources from other servers
    pub include_external: bool,
}

/// Sorts a vector or resources by some property.
#[tracing::instrument]
pub fn sort_resources(
    mut resources: ResourceCollection,
    sort_by: &str,
    sort_desc: bool,
) -> ResourceCollection {
    resources.sort_by(|a, b| {
        let val_a = a.get(sort_by);
        let val_b = b.get(sort_by);
        if val_a.is_err() || val_b.is_err() {
            return std::cmp::Ordering::Greater;
        };
        if val_b.unwrap().to_string() > val_a.unwrap().to_string() {
            if sort_desc {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Less
            }
        } else if sort_desc {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    });
    resources
}

impl Collection {
    /// Constructs a Collection, which is a paginated list of items with some sorting applied.
    /// Gets the required data from the store.
    /// Applies sorting settings.
    #[tracing::instrument(skip(store))]
    pub fn collect_members(
        store: &impl Storelike,
        collection_builder: crate::collections::CollectionBuilder,
        for_agent: &ForAgent,
    ) -> AtomicResult<Collection> {
        if collection_builder.page_size < 1 {
            return Err("Page size must be greater than 0".into());
        }

        // Warning: this _assumes_ that the Value is a string.
        // This will work for most datatypes, but not for things like resource arrays!
        // We could improve this by taking the datatype of the `property`, and parsing the string.
        let value_filter = collection_builder
            .value
            .as_ref()
            .map(|val| Value::String(val.clone()));

        let q = Query {
            property: collection_builder.property.clone(),
            value: value_filter,
            limit: Some(collection_builder.page_size),
            start_val: None,
            end_val: None,
            offset: collection_builder.page_size * collection_builder.current_page,
            sort_by: collection_builder.sort_by.clone(),
            sort_desc: collection_builder.sort_desc,
            include_external: collection_builder.include_external,
            include_nested: collection_builder.include_nested,
            for_agent: for_agent.clone(),
        };

        let query_result = store.query(&q)?;
        let members = query_result.subjects;
        let members_nested = Some(query_result.resources);
        let total_items = query_result.count;
        let pages_fraction = total_items as f64 / collection_builder.page_size as f64;
        let total_pages = pages_fraction.ceil() as usize;
        if collection_builder.current_page > total_pages {
            return Err(format!(
                "Page number out of bounds, got {}, max {}",
                collection_builder.current_page, total_pages
            )
            .into());
        }

        let collection = Collection {
            total_pages,
            members,
            members_nested,
            total_items,
            subject: collection_builder.subject,
            property: collection_builder.property,
            value: collection_builder.value,
            sort_by: collection_builder.sort_by,
            sort_desc: collection_builder.sort_desc,
            current_page: collection_builder.current_page,
            page_size: collection_builder.page_size,
            name: collection_builder.name,
            include_nested: collection_builder.include_nested,
            include_external: collection_builder.include_external,
        };
        Ok(collection)
    }

    pub fn to_resource(&self, store: &impl Storelike) -> AtomicResult<crate::Resource> {
        let mut resource = crate::Resource::new(self.subject.clone());
        self.add_to_resource(&mut resource, store)?;
        Ok(resource)
    }

    /// Adds the Collection props to an existing Resource.
    pub fn add_to_resource(
        &self,
        resource: &mut Resource,
        store: &impl Storelike,
    ) -> AtomicResult<crate::Resource> {
        resource.set_propval(
            crate::urls::COLLECTION_MEMBERS.into(),
            if let Some(nested_members) = &self.members_nested {
                nested_members.clone().into()
            } else {
                self.members.clone().into()
            },
            store,
        )?;
        if let Some(prop) = &self.property {
            resource.set_propval_string(crate::urls::COLLECTION_PROPERTY.into(), prop, store)?;
        }
        if self.include_nested {
            resource.set_propval_string(
                crate::urls::COLLECTION_INCLUDE_NESTED.into(),
                "true",
                store,
            )?;
        }
        if self.include_external {
            resource.set_propval_string(
                crate::urls::COLLECTION_INCLUDE_EXTERNAL.into(),
                "true",
                store,
            )?;
        }
        if let Some(val) = &self.value {
            resource.set_propval_string(crate::urls::COLLECTION_VALUE.into(), val, store)?;
        }
        if let Some(val) = &self.name {
            resource.set_propval_string(crate::urls::NAME.into(), val, store)?;
        }
        resource.set_propval(
            crate::urls::COLLECTION_MEMBER_COUNT.into(),
            self.total_items.into(),
            store,
        )?;
        let classes: Vec<String> = vec![crate::urls::COLLECTION.into()];
        resource.set_propval(crate::urls::IS_A.into(), classes.into(), store)?;
        resource.set_propval(
            crate::urls::COLLECTION_TOTAL_PAGES.into(),
            self.total_pages.into(),
            store,
        )?;
        resource.set_propval(
            crate::urls::COLLECTION_CURRENT_PAGE.into(),
            self.current_page.into(),
            store,
        )?;
        resource.set_propval(
            crate::urls::COLLECTION_PAGE_SIZE.into(),
            self.page_size.into(),
            store,
        )?;

        Ok(resource.to_owned())
    }
}

/// Builds a collection from query params and the passed Collection resource.
/// The query params are used to override the stored Collection resource properties.
/// This also sets defaults for Collection properties when fields are missing
#[tracing::instrument(skip(store, query_params))]
pub fn construct_collection_from_params(
    store: &impl Storelike,
    query_params: url::form_urlencoded::Parse,
    resource: &mut Resource,
    for_agent: &ForAgent,
) -> AtomicResult<Resource> {
    let mut sort_by = None;
    let mut sort_desc = false;
    let mut current_page = 0;
    let mut page_size = DEFAULT_PAGE_SIZE;
    let mut value = None;
    let mut property = None;
    let mut name = None;
    let mut include_nested = false;
    let mut include_external = false;

    if let Ok(val) = resource.get(urls::COLLECTION_PROPERTY) {
        property = Some(val.to_string());
    }
    if let Ok(val) = resource.get(urls::COLLECTION_PAGE_SIZE) {
        page_size = val.to_int()?.try_into().unwrap_or(DEFAULT_PAGE_SIZE);
    }
    if let Ok(val) = resource.get(urls::COLLECTION_VALUE) {
        value = Some(val.to_string());
    }
    if let Ok(val) = resource.get(urls::NAME) {
        name = Some(val.to_string());
    }
    if let Ok(val) = resource.get(urls::COLLECTION_INCLUDE_NESTED) {
        include_nested = val.to_bool()?;
    }
    if let Ok(val) = resource.get(urls::COLLECTION_INCLUDE_EXTERNAL) {
        include_external = val.to_bool()?;
    }
    for (k, v) in query_params {
        match k.as_ref() {
            "property" => property = Some(v.to_string()),
            "value" => value = Some(v.to_string()),
            "sort_by" => sort_by = Some(v.to_string()),
            "sort_desc" => sort_desc = v.parse::<bool>()?,
            "current_page" => current_page = v.parse::<usize>()?,
            "page_size" => page_size = v.parse::<usize>()?,
            "include_nested" => include_nested = v.parse::<bool>()?,
            "include_external" => include_external = v.parse::<bool>()?,
            e => {
                return Err(format!("Invalid query param: {}", e).into());
            }
        };
    }
    let collection_builder = crate::collections::CollectionBuilder {
        subject: resource.get_subject().into(),
        property,
        value,
        sort_by,
        sort_desc,
        current_page,
        page_size,
        name,
        include_nested,
        include_external,
    };
    let collection = Collection::collect_members(store, collection_builder, for_agent)?;
    collection.add_to_resource(resource, store)
}

/// Creates a Collection resource in the Store for a Class, for example `/documents`.
/// Does not save it, though.
pub fn create_collection_resource_for_class(
    store: &impl Storelike,
    class_subject: &str,
) -> AtomicResult<Resource> {
    let class = store.get_class(class_subject)?;

    // We use the `Collections` collection as the parent for all collections.
    // This also influences their URLs.
    let is_collections_collection = class.subject == urls::COLLECTION;

    // Pluralize the shortname
    let pluralized = match class.shortname.as_ref() {
        "class" => "classes".to_string(),
        "property" => "properties".to_string(),
        other => format!("{}s", other),
    };

    let path = if is_collections_collection {
        "/collections".to_string()
    } else {
        format!("/collections/{}", pluralized)
    };

    let mut collection = CollectionBuilder::class_collection(&class.subject, &path, store);

    collection.sort_by = match class_subject {
        urls::COMMIT => Some(urls::CREATED_AT.to_string()),
        urls::CLASS | urls::PROPERTY => Some(urls::SHORTNAME.to_string()),
        urls::COLLECTION => Some(urls::COLLECTION_VALUE.to_string()),
        _other => None,
    };

    collection.sort_desc = match class_subject {
        urls::COMMIT => true,
        _other => false,
    };

    let mut collection_resource = collection.to_resource(store)?;

    let drive = store
        .get_self_url()
        .ok_or("No self_url present in store, can't populate collections")?;

    // Let the Collections collection be the top level item
    let parent = if is_collections_collection {
        drive.to_string()
    } else {
        drive
            .set_route(crate::atomic_url::Routes::Collections)
            .to_string()
    };

    collection_resource.set_propval_string(urls::PARENT.into(), &parent, store)?;

    collection_resource.set_propval_string(urls::NAME.into(), &pluralized, store)?;

    // Should we use save_locally, which creates commits, or add_resource_unsafe, which is faster?
    Ok(collection_resource)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::urls;
    use crate::Storelike;

    #[test]
    fn create_collection() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let collection_builder = CollectionBuilder {
            subject: "test_subject".into(),
            property: Some(urls::IS_A.into()),
            value: Some(urls::CLASS.into()),
            sort_by: None,
            sort_desc: false,
            page_size: DEFAULT_PAGE_SIZE,
            current_page: 0,
            name: Some("Test collection".into()),
            include_nested: false,
            include_external: false,
        };
        let collection =
            Collection::collect_members(&store, collection_builder, &ForAgent::Sudo).unwrap();
        assert!(collection.members.contains(&urls::PROPERTY.into()));
    }

    #[test]
    fn create_collection_2() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let collection_builder = CollectionBuilder {
            subject: "test_subject".into(),
            property: Some(urls::IS_A.into()),
            value: Some(urls::CLASS.into()),
            sort_by: None,
            sort_desc: false,
            page_size: DEFAULT_PAGE_SIZE,
            current_page: 0,
            name: None,
            include_nested: false,
            include_external: false,
        };
        let collection =
            Collection::collect_members(&store, collection_builder, &ForAgent::Sudo).unwrap();
        assert!(collection.members.contains(&urls::PROPERTY.into()));

        let resource_collection = &collection.to_resource(&store).unwrap();
        resource_collection
            .get(urls::COLLECTION_INCLUDE_NESTED)
            .unwrap_err();
    }

    #[test]
    fn create_collection_nested_members_and_sorting() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let collection_builder = CollectionBuilder {
            subject: "test_subject".into(),
            property: Some(urls::IS_A.into()),
            value: Some(urls::CLASS.into()),
            sort_by: Some(urls::SHORTNAME.into()),
            sort_desc: false,
            page_size: DEFAULT_PAGE_SIZE,
            current_page: 0,
            name: None,
            // The important bit here
            include_nested: true,
            include_external: false,
        };
        let collection =
            Collection::collect_members(&store, collection_builder, &ForAgent::Sudo).unwrap();
        let first_resource = &collection.members_nested.clone().unwrap()[0];
        assert!(first_resource.get_subject().contains("Agent"));

        let resource_collection = &collection.to_resource(&store).unwrap();
        let val = resource_collection
            .get(urls::COLLECTION_INCLUDE_NESTED)
            .unwrap()
            .to_bool()
            .unwrap();
        assert!(val, "Include nested must be true");
    }

    #[cfg(feature = "db")]
    #[test]
    fn get_collection() {
        let store = crate::db::test::DB.lock().unwrap().clone();
        let subjects: Vec<String> = store
            .all_resources(false)
            .into_iter()
            .map(|r| r.get_subject().into())
            .collect();
        println!("{:?}", subjects);
        let collections_collection = store
            .get_resource_extended(
                &format!("{}collections", store.get_server_url()),
                false,
                &ForAgent::Public,
            )
            .unwrap();
        assert!(
            collections_collection
                .get(urls::COLLECTION_PROPERTY)
                .unwrap()
                .to_string()
                == urls::IS_A
        );
        let member_count = collections_collection
            .get(urls::COLLECTION_MEMBER_COUNT)
            .unwrap();
        println!("Member Count is {}", member_count);
        assert!(
            member_count.to_int().unwrap() > 10,
            "Member count is too small"
        );
    }

    #[test]
    #[ignore]
    // TODO: This currently only tests atomicdata.dev, should test local resources. These need to be rewritten
    fn get_collection_params() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();

        let collection_page_size = store
            .get_resource_extended(
                "https://atomicdata.dev/classes?page_size=1",
                false,
                &ForAgent::Public,
            )
            .unwrap();
        assert!(
            collection_page_size
                .get(urls::COLLECTION_PAGE_SIZE)
                .unwrap()
                .to_string()
                == "1"
        );
        let collection_page_nr = store
            .get_resource_extended(
                "https://atomicdata.dev/classes?current_page=2&page_size=1",
                false,
                &ForAgent::Public,
            )
            .unwrap();
        assert!(
            collection_page_nr
                .get(urls::COLLECTION_PAGE_SIZE)
                .unwrap()
                .to_string()
                == "1"
        );
        let members_vec = match collection_page_nr.get(urls::COLLECTION_MEMBERS).unwrap() {
            crate::Value::ResourceArray(vec) => vec,
            _ => panic!(),
        };
        assert!(members_vec.len() == 1);
        assert!(
            collection_page_nr
                .get(urls::COLLECTION_CURRENT_PAGE)
                .unwrap()
                .to_string()
                == "2"
        );
    }

    #[test]
    fn sorting_resources() {
        let prop = urls::DESCRIPTION.to_string();
        let mut a = Resource::new("first".into());
        a.set_propval_unsafe(prop.clone(), Value::Markdown("1".into()));
        let mut b = Resource::new("second".into());
        b.set_propval_unsafe(prop.clone(), Value::Markdown("2".into()));
        let c = Resource::new("third_missing_property".into());

        let asc = vec![a.clone(), b.clone(), c.clone()];
        let sorted = sort_resources(asc.clone(), &prop, false);
        assert_eq!(a.get_subject(), sorted[0].get_subject());
        assert_eq!(b.get_subject(), sorted[1].get_subject());
        assert_eq!(c.get_subject(), sorted[2].get_subject());

        let sorted_desc = sort_resources(asc, &prop, true);
        assert_eq!(b.get_subject(), sorted_desc[0].get_subject());
        assert_eq!(a.get_subject(), sorted_desc[1].get_subject());
        assert_eq!(
            c.get_subject(),
            sorted_desc[2].get_subject(),
            "c is missing the sorted property - it should _alway_ be last"
        );
    }
}
