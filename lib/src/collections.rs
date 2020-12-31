//! Collections are dynamic resources that refer to multiple resources.
//! They are constructed using a TPF query

use crate::{errors::AtomicResult, urls, Resource, Storelike};

#[derive(Debug)]
pub struct TPFQuery {
    pub subject: Option<String>,
    pub property: Option<String>,
    pub value: Option<String>,
}

/// Used to construct a Collection.
/// Has to be constructed using `Collection::new()` or `storelike.new_collection()`.
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
}

/// Dynamic resource used for ordering, filtering and querying content.
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
}

impl Collection {
    /// Constructs a Collection, which is a paginated list of items with some sorting applied.
    pub fn new(
        store: &impl Storelike,
        collection_builder: crate::collections::CollectionBuilder,
    ) -> AtomicResult<Collection> {
        // Execute the TPF query, get all the subjects.
        let atoms = store.tpf(
            None,
            collection_builder.property.as_deref(),
            collection_builder.value.as_deref(),
        )?;
        // Iterate over the fetched resources
        let subjects: Vec<String> = atoms.iter().map(|atom| atom.subject.clone()).collect();
        // Sort the resources (TODO), use sortBy and sortDesc
        if collection_builder.sort_by.is_some() {
            return Err("Sorting is not yet implemented".into());
        }
        let sorted_subjects: Vec<String> = subjects;
        let mut all_pages: Vec<Vec<String>> = Vec::new();
        let mut page: Vec<String> = Vec::new();
        let current_page = collection_builder.current_page;
        for (i, subject) in sorted_subjects.iter().enumerate() {
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
            if i == sorted_subjects.len() - 1 {
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
        let total_items = sorted_subjects.len();
        // Construct the pages (TODO), use pageSize
        let total_pages = (total_items + collection_builder.page_size - 1) / collection_builder.page_size;
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
        };
        Ok(collection)
    }

    pub fn to_resource(
        &self,
    ) -> AtomicResult<crate::Resource> {
        // TODO: Should not persist, because now it is spammimg the store!
        // let mut resource = crate::Resource::new_instance(crate::urls::COLLECTION, store)?;
        let mut resource = crate::Resource::new(self.subject.clone());
        resource.set_propval(
            crate::urls::COLLECTION_MEMBERS.into(),
            self.members.clone().into(),
        )?;
        if let Some(prop) = self.property.clone() {
            resource.set_propval(crate::urls::COLLECTION_PROPERTY.into(), prop.into())?;
        }
        if let Some(prop) = self.value.clone() {
            resource.set_propval(crate::urls::COLLECTION_VALUE.into(), prop.into())?;
        }
        resource.set_propval(
            crate::urls::COLLECTION_MEMBER_COUNT.into(),
            self.total_items.clone().into(),
        )?;
        let mut classes: Vec<String> = Vec::new();
        classes.push(crate::urls::COLLECTION.into());
        resource.set_propval(
            crate::urls::IS_A.into(),
            classes.into(),
        )?;
        resource.set_propval(
            crate::urls::COLLECTION_TOTAL_PAGES.into(),
            self.total_pages.clone().into(),
        )?;
        resource.set_propval(
            crate::urls::COLLECTION_CURRENT_PAGE.into(),
            self.current_page.clone().into(),
        )?;
        resource.set_propval(
            crate::urls::COLLECTION_PAGE_SIZE.into(),
            self.page_size.clone().into(),
        )?;
        // Maybe include items directly
        Ok(resource)
    }
}

/// Builds a collection from query params
pub fn construct_collection(
    store: &impl Storelike,
    query_params: url::form_urlencoded::Parse,
    resource: Resource,
) -> AtomicResult<Resource> {
    let mut sort_by = None;
    let mut sort_desc = false;
    let mut current_page = 0;
    let mut page_size = 100;
    let mut value = None;
    let mut property = None;

    if let Ok(val) = resource.get(urls::COLLECTION_PROPERTY) {
        property = Some(val.to_string());
    }
    if let Ok(val) = resource.get(urls::COLLECTION_VALUE) {
        value = Some(val.to_string());
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
    };
    let collection = Collection::new(store, collection_builder)?;
    Ok(collection.to_resource()?)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::urls;
    use crate::Storelike;

    #[test]
    fn create_collection() {
        let store = crate::Store::init();
        store.populate().unwrap();
        // Get all Classes, sorted by shortname
        let collection_builder = CollectionBuilder {
            subject: "test_subject".into(),
            property: Some(urls::IS_A.into()),
            value: Some(urls::CLASS.into()),
            sort_by: None,
            sort_desc: false,
            page_size: 1000,
            current_page: 0,
        };
        let collection = store.new_collection(collection_builder).unwrap();
        assert!(collection.members.contains(&urls::PROPERTY.into()));
    }

    #[test]
    fn create_collection_2() {
        let store = crate::Store::init();
        store.populate().unwrap();
        // Get all Classes, sorted by shortname
        let collection_builder = CollectionBuilder {
            subject: "test_subject".into(),
            property: Some(urls::IS_A.into()),
            value: Some(urls::CLASS.into()),
            sort_by: None,
            sort_desc: false,
            page_size: 1000,
            current_page: 0,
        };
        let collection = Collection::new(&store, collection_builder).unwrap();
        assert!(collection.members.contains(&urls::PROPERTY.into()));
    }

    #[test]
    fn get_collection() {
        let store = crate::Store::init();
        store.populate().unwrap();
        let collection = store
            .get_resource_extended("https://atomicdata.dev/classes")
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
        assert!(
            collection
                .get(urls::COLLECTION_MEMBER_COUNT)
                .unwrap()
                .to_string()
                == "6"
        );
    }

    #[test]
    fn get_collection_params() {
        let store = crate::Store::init();
        store.populate().unwrap();

        let collection_page_size = store
            .get_resource_extended("https://atomicdata.dev/classes?page_size=1")
            .unwrap();
        assert!(
            collection_page_size
                .get(urls::COLLECTION_PAGE_SIZE)
                .unwrap()
                .to_string()
                == "1"
        );
        let collection_page_nr = store
            .get_resource_extended("https://atomicdata.dev/classes?current_page=2&page_size=1")
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
