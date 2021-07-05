//! Collections are dynamic resources that refer to multiple resources.
//! They are constructed using a TPF query
use crate::{Resource, Storelike, errors::AtomicResult, storelike::ResourceCollection, urls};

#[derive(Debug)]
pub struct TPFQuery {
    pub subject: Option<String>,
    pub property: Option<String>,
    pub value: Option<String>,
}

const DEFAULT_PAGE_SIZE: usize = 30;

/// Used to construct a Collection. Does not contain results / members.
/// Has to be constructed using `Collection::new()` or `storelike.new_collection()`.
#[derive(Debug)]
pub struct CollectionBuilder {
    /// Full Subject URL of the resource, including query parameters
    pub subject: String,
    /// The TPF property which the results are to be filtered by
    pub property: Option<String>,
    /// The TPF value which the results are to be filtered by
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
}

impl CollectionBuilder {
    /// Converts a CollectionBuilder into a Resource.
    /// Note that this does not calculate any members, and it does not generate any pages.
    /// If that is what you need, use `.into_resource`
    pub fn to_resource(&self, store: &impl Storelike) -> AtomicResult<crate::Resource> {
        let mut resource = crate::Resource::new_instance(urls::COLLECTION, store)?;
        resource.set_subject(self.subject.clone());
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
            self.page_size.clone().into(),
            store,
        )?;
        // Maybe include items directly
        Ok(resource)
    }

    /// Default CollectionBuilder for Classes. Finds all resources by class URL. Has sensible defaults.
    pub fn class_collection(class_url: &str, path: &str, store: &impl Storelike) -> CollectionBuilder {
        CollectionBuilder {
            subject: format!("{}/{}", store.get_base_url(), path),
            property: Some(urls::IS_A.into()),
            value: Some(class_url.into()),
            sort_by: None,
            sort_desc: false,
            page_size: DEFAULT_PAGE_SIZE,
            current_page: 0,
            name: Some(format!("{} collection", path)),
        }
    }

    /// Converts the CollectionBuilder into a collection, with Members
    pub fn into_collection(self, store: &impl Storelike) -> AtomicResult<Collection> {
        Collection::new_with_members(store, self)
    }
}

/// Dynamic resource used for ordering, filtering and querying content.
/// Contains members / results. Use CollectionBuilder if you don't (yet) need the results.
/// Features pagination.
#[derive(Debug)]
pub struct Collection {
    /// Full Subject URL of the resource, including query parameters
    pub subject: String,
    /// The TPF property which the results are to be filtered by
    pub property: Option<String>,
    /// The TPF value which the results are to be filtered by
    pub value: Option<String>,
    /// The actual items that you're interested in. List the member subjects of the current page.
    pub members: Vec<String>,
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
}

/// Sorts a vector or resources by some property.
fn sort_resources(mut resources: ResourceCollection, sort_by: &str, sort_desc: bool) -> ResourceCollection {
    resources.sort_by(
        |a, b|
        {
            let val_a = a.get(sort_by);
            let val_b = b.get(sort_by);
            if val_a.is_err() || val_b.is_err() {
                return std::cmp::Ordering::Equal
            }
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
        }
    );
    resources
}

impl Collection {
    /// Constructs a Collection, which is a paginated list of items with some sorting applied.
    /// Gets the required data from the store.
    /// Applies sorting settings.
    pub fn new_with_members(
        store: &impl Storelike,
        collection_builder: crate::collections::CollectionBuilder,
    ) -> AtomicResult<Collection> {
        if collection_builder.page_size < 1 {
            return Err("Page size must be greater than 0".into());
        }
        // Execute the TPF query, get all the subjects.
        let atoms = store.tpf(
            None,
            collection_builder.property.as_deref(),
            collection_builder.value.as_deref(),
            // Collections only show items from inside this store. Maybe later add this as an option to collections
            false
        )?;
        let mut subjects: Vec<String> = atoms.iter().map(|atom| atom.subject.clone()).collect();
        // Default to no sorting
        if collection_builder.sort_by.is_some() {
            let mut resources = Vec::new();
            for subject in subjects.clone() {
                resources.push(store.get_resource(&subject)?)
            };
            // TODO: Include these resources in the response! They're already fetched. Should speed things up.
            // https://github.com/joepio/atomic/issues/62
            resources = sort_resources(resources, &collection_builder.sort_by.clone().unwrap(), collection_builder.sort_desc);
            subjects.clear();
            for resource in resources {
                subjects.push(resource.get_subject().clone())
            }
        }
        let mut all_pages: Vec<Vec<String>> = Vec::new();
        let mut page: Vec<String> = Vec::new();
        let current_page = collection_builder.current_page;
        for (i, subject) in subjects.iter().enumerate() {
            page.push(subject.into());
            if page.len() >= collection_builder.page_size {
                all_pages.push(page);
                page = Vec::new();
                // No need to calculte more than necessary
                if all_pages.len() > current_page {
                    break;
                }
            }
            // Add the last page when handling the last subject
            if i == subjects.len() - 1 {
                all_pages.push(page);
                break;
            }
        }
        if all_pages.is_empty() {
            all_pages.push(Vec::new())
        }
        // Maybe I should default to last page, if current_page is too high?
        let members = all_pages
            .get(current_page)
            .ok_or("Page number is too high")?
            .clone();
        let total_items = subjects.len();
        // Construct the pages (TODO), use pageSize
        let total_pages =
            (total_items + collection_builder.page_size - 1) / collection_builder.page_size;
        let collection = Collection {
            total_pages,
            members,
            total_items,
            subject: collection_builder.subject,
            property: collection_builder.property,
            value: collection_builder.value,
            sort_by: collection_builder.sort_by,
            sort_desc: collection_builder.sort_desc,
            current_page: collection_builder.current_page,
            page_size: collection_builder.page_size,
            name: collection_builder.name,
        };
        Ok(collection)
    }

    pub fn to_resource(&self, store: &impl Storelike) -> AtomicResult<crate::Resource> {
        let mut resource = crate::Resource::new(self.subject.clone());
        self.add_to_resource(&mut resource, store)?;
        Ok(resource)
    }

    /// Adds the Collection props to an existing Resource.
    pub fn add_to_resource(&self, resource: &mut Resource, store: &impl Storelike) -> AtomicResult<crate::Resource> {
        resource.set_propval(
            crate::urls::COLLECTION_MEMBERS.into(),
            self.members.clone().into(),
            store,
        )?;
        if let Some(prop) = &self.property {
            resource.set_propval_string(crate::urls::COLLECTION_PROPERTY.into(), prop, store)?;
        }
        if let Some(val) = &self.value {
            resource.set_propval_string(crate::urls::COLLECTION_VALUE.into(), val, store)?;
        }
        if let Some(val) = &self.name {
            resource.set_propval_string(crate::urls::NAME.into(), val, store)?;
        }
        resource.set_propval(
            crate::urls::COLLECTION_MEMBER_COUNT.into(),
            self.total_items.clone().into(),
            store,
        )?;
        let classes: Vec<String> = vec![crate::urls::COLLECTION.into()];
        resource.set_propval(crate::urls::IS_A.into(), classes.into(), store)?;
        resource.set_propval(
            crate::urls::COLLECTION_TOTAL_PAGES.into(),
            self.total_pages.clone().into(),
            store,
        )?;
        resource.set_propval(
            crate::urls::COLLECTION_CURRENT_PAGE.into(),
            self.current_page.clone().into(),
            store,
        )?;
        resource.set_propval(
            crate::urls::COLLECTION_PAGE_SIZE.into(),
            self.page_size.clone().into(),
            store,
        )?;
        // Maybe include items directly
        Ok(resource.to_owned())
    }
}

/// Builds a collection from query params
pub fn construct_collection(
    store: &impl Storelike,
    query_params: url::form_urlencoded::Parse,
    resource: &mut Resource,
) -> AtomicResult<Resource> {
    let mut sort_by = None;
    let mut sort_desc = false;
    let mut current_page = 0;
    let mut page_size = DEFAULT_PAGE_SIZE;
    let mut value = None;
    let mut property = None;
    let mut name = None;

    if let Ok(val) = resource.get(urls::COLLECTION_PROPERTY) {
        property = Some(val.to_string());
    }
    if let Ok(val) = resource.get(urls::COLLECTION_VALUE) {
        value = Some(val.to_string());
    }
    if let Ok(val) = resource.get(urls::NAME) {
        name = Some(val.to_string());
    }
    for (k, v) in query_params {
        match k.as_ref() {
            "property" => property = Some(v.to_string()),
            "value" => value = Some(v.to_string()),
            "sort_by" => sort_by = Some(v.to_string()),
            // TODO: parse bool
            "sort_desc" => sort_desc = true,
            "current_page" => current_page = v.parse::<usize>()?,
            "page_size" => page_size = v.parse::<usize>()?,
            _ => {}
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
    };
    let collection = Collection::new_with_members(store, collection_builder)?;
    collection.add_to_resource(resource, store)
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
        // Get all Classes, sorted by shortname
        let collection_builder = CollectionBuilder {
            subject: "test_subject".into(),
            property: Some(urls::IS_A.into()),
            value: Some(urls::CLASS.into()),
            sort_by: None,
            sort_desc: false,
            page_size: DEFAULT_PAGE_SIZE,
            current_page: 0,
            name: Some("Test collection".into())
        };
        let collection = Collection::new_with_members(&store, collection_builder).unwrap();
        assert!(collection.members.contains(&urls::PROPERTY.into()));
    }

    #[test]
    fn create_collection_2() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        // Get all Classes, sorted by shortname
        let collection_builder = CollectionBuilder {
            subject: "test_subject".into(),
            property: Some(urls::IS_A.into()),
            value: Some(urls::CLASS.into()),
            sort_by: None,
            sort_desc: false,
            page_size: DEFAULT_PAGE_SIZE,
            current_page: 0,
            name: None,
        };
        let collection = Collection::new_with_members(&store, collection_builder).unwrap();
        assert!(collection.members.contains(&urls::PROPERTY.into()));
    }

    #[test]
    fn get_collection() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let collection = store
            .get_resource_extended("https://atomicdata.dev/collections/class")
            .unwrap();
        assert!(
            collection
                .get(urls::COLLECTION_PROPERTY)
                .unwrap()
                .to_string()
                == urls::IS_A
        );
        println!(
            "Count is {}",
            collection
                .get(urls::COLLECTION_MEMBER_COUNT)
                .unwrap()
                .to_string()
        );
        assert_eq!(
            collection
                .get(urls::COLLECTION_MEMBER_COUNT)
                .unwrap()
                .to_string()
                , "10"
        );
    }

    #[test]
    fn get_collection_params() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();

        let collection_page_size = store
            .get_resource_extended("https://atomicdata.dev/collections/class?page_size=1")
            .unwrap();
        assert!(
            collection_page_size
                .get(urls::COLLECTION_PAGE_SIZE)
                .unwrap()
                .to_string()
                == "1"
        );
        let collection_page_nr = store
            .get_resource_extended("https://atomicdata.dev/collections/class?current_page=2&page_size=1")
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
}
