//! Collections are dynamic resources that refer to multiple resources.
//! They are constructed using a TPF query

use crate::{errors::AtomicResult, urls, Resource, Storelike};

#[derive(Debug)]
pub struct TPFQuery {
    pub subject: Option<String>,
    pub property: Option<String>,
    pub value: Option<String>,
}

pub struct CollectionBuilder {
    pub subject: String,
    pub property: Option<String>,
    pub value: Option<String>,
    pub sort_by: Option<String>,
    pub sort_desc: bool,
    pub current_page: usize,
    pub page_size: usize,
}

/// Dynamic resource used for ordering, filtering and querying content.
/// Features pagination.
#[derive(Debug)]
pub struct Collection {
    // Full Subject URL of the resource, including query parameters
    pub subject: String,
    /// The TPF property which the results are to be filtered by
    pub property: Option<String>,
    /// The TPF value which the results are to be filtered by
    pub value: Option<String>,
    // The actual items that you're interested in. List the member subjects of the current page.
    pub members: Vec<String>,
    // URL of the value to sort by
    pub sort_by: Option<String>,
    // Sorts ascending by default
    pub sort_desc: bool,
    // How many items per page
    pub page_size: usize,
    // Current page number, defaults to 0 (first page)
    pub current_page: usize,
    // Total number of items
    pub total_items: usize,
    // Total number of pages
    pub total_pages: usize,
}

impl Collection {
    /// Constructs a Collection, which is a paginated list of items with some sorting applied.
    pub fn new (
        store: &dyn Storelike,
        collection: crate::collections::CollectionBuilder,
    ) -> AtomicResult<Collection> {
        // Execute the TPF query, get all the subjects.
        let atoms = store.tpf(
            None,
            collection.property.as_deref(),
            collection.value.as_deref(),
        )?;
        // Iterate over the fetched resources
        let subjects: Vec<String> = atoms.iter().map(|atom| atom.subject.clone()).collect();
        // Sort the resources (TODO), use sortBy and sortDesc
        if collection.sort_by.is_some() {
            return Err("Sorting is not yet implemented".into());
        }
        let sorted_subjects: Vec<String> = subjects;
        let mut all_pages: Vec<Vec<String>> = Vec::new();
        let mut page: Vec<String> = Vec::new();
        let current_page = collection.current_page;
        for (i, subject) in sorted_subjects.iter().enumerate() {
            page.push(subject.into());
            if page.len() >= collection.page_size {
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
        let total_pages = (total_items + collection.page_size - 1) / collection.page_size;
        let collection_return = Collection {
            total_pages,
            members,
            total_items,
            subject: collection.subject,
            property: collection.property,
            value: collection.value,
            sort_by: collection.sort_by,
            sort_desc: collection.sort_desc,
            current_page: collection.current_page,
            page_size: collection.page_size,
        };
        Ok(collection_return)
    }

    pub fn to_resource<'a>(
        &self,
        store: &'a dyn crate::Storelike,
    ) -> AtomicResult<crate::Resource<'a>> {
        // TODO: Should not persist, because now it is spammimg the store!
        // let mut resource = crate::Resource::new_instance(crate::urls::COLLECTION, store)?;
        let mut resource = crate::Resource::new(self.subject.clone(), store);
        resource.set_propval(crate::urls::MEMBERS.into(), self.members.clone().into())?;
        if let Some(prop) = self.property.clone() {
            resource.set_propval(crate::urls::COLLECTION_PROPERTY.into(), prop.into())?;
        }
        if let Some(prop) = self.value.clone() {
            resource.set_propval(crate::urls::COLLECTION_VALUE.into(), prop.into())?;
        }
        resource.set_propval(
            crate::urls::COLLECTION_ITEM_COUNT.into(),
            self.total_items.clone().into(),
        )?;
        resource.set_propval(
            crate::urls::COLLECTION_TOTAL_PAGES.into(),
            self.total_pages.clone().into(),
        )?;
        resource.set_propval(
            crate::urls::COLLECTION_CURRENT_PAGE.into(),
            self.current_page.clone().into(),
        )?;
        // Maybe include items directly
        Ok(resource)
    }
}

/// Builds a collection from query params
pub fn construct_collection<'a>(
    store: &'a dyn Storelike,
    query_params: url::form_urlencoded::Parse,
    resource: Resource,
) -> AtomicResult<Resource<'a>> {
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
    return Ok(collection.to_resource(store)?);
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
                .get(urls::COLLECTION_ITEM_COUNT)
                .unwrap()
                .to_string()
        );
        assert!(
            collection
                .get(urls::COLLECTION_ITEM_COUNT)
                .unwrap()
                .to_string()
                == "6"
        );
    }
}
