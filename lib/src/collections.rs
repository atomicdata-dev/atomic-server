//! Collections are dynamic resources that refer to multiple resources.
//! They are constructed using a TPF query

use crate::errors::AtomicResult;

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
  pub fn to_resource<'a>(&self, store: &'a dyn crate::Storelike) -> AtomicResult<crate::Resource<'a>> {
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
    // resource.set_propval(crate::urls::COLLECTION_ITEM_COUNT.into(), self.members.clone().into())?;
    // Maybe include items directly
    Ok(resource)
  }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Storelike;
    use crate::urls;

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
      let collection = store.get_resource_extended("https://atomicdata.dev/classes").unwrap();
      assert!(collection.get(urls::COLLECTION_PROPERTY).unwrap().to_string() == urls::IS_A)
    }
}
