use crate::errors::AtomicResult;

#[derive(Debug)]
pub struct TPFQuery {
  pub subject: Option<String>,
  pub property: Option<String>,
  pub value: Option<String>,
}

/// Dynamic resource used for ordering, filtering and querying content.
/// Features pagination.
#[derive(Debug)]
pub struct Collection {
  // The set of triples that form the basis of the data
  pub tpf: TPFQuery,
  // List of all the pages.
  pub pages: Vec<Page>,
  // List of all the member subjects.
  pub members: Vec<String>,
  // URL of the value to sort by
  pub sort_by: Option<String>,
  // Sorts ascending by default
  pub sort_desc: bool,
  // How many items per page
  pub page_size: u8,
  // Current page number, defaults to 0 (first page)
  pub current_page: u8,
  // Total number of items
  pub total_items: u8,
  // Total number of pages
  pub total_pages: u8,
}

impl Collection {
  pub fn to_resource<'a>(&self, store: &'a dyn crate::Storelike) -> AtomicResult<crate::Resource<'a>> {
    // TODO: Should not persist, because now it is spammimg the store!
    let mut resource = crate::Resource::new_instance(crate::urls::COLLECTION, store)?;
    // Here a propval must be set of a NESTED property...
    // resource.set_by_shortname("pages", self.pages)?;
    // Maybe include items directly
    resource.set_propval(crate::urls::MEMBERS.into(), self.members.clone().into())?;
    Ok(resource)
  }
}

/// A single page of a Collection
#[derive(Debug)]
pub struct Page {
  // partOf: Collection,
  // The individual items in the page
  pub members: Vec<String>,
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
        let tpf = TPFQuery {
            subject: None,
            property: Some(urls::IS_A.into()),
            value: Some(urls::CLASS.into()),
        };
        // Get all Classes, sorted by shortname
        let collection = store.get_collection(tpf, Some(urls::SHORTNAME.into()), false, 1, 1).unwrap();
        assert!(collection.pages[0].members.contains(&urls::PROPERTY.into()));
    }
}
