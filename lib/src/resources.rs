//! A resource is a set of Atoms that share a URL

use crate::errors::AtomicResult;
use crate::values::Value;
use crate::{
    mapping::is_url,
    storelike::{Class, Property},
    Atom, Storelike,
};
use std::collections::HashMap;

/// A Resource is a set of Atoms that shares a single Subject.
/// A Resource only contains valid Values, but it _might_ lack required properties.
/// All changes to the Resource are immediately applied to the Store as well.
// #[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resource<'a> {
    /// A hashMap of all the Property Value combinations
    propvals: PropVals,
    subject: String,
    // The isA relationship of the resource
    // Useful for quick access to shortnames and datatypes
    // Should be an empty vector if it's checked, should be None if unknown
    classes: Option<Vec<Class>>,
    /// A reference to the store
    store: &'a dyn Storelike,
    /// A hashmap of nested Resources.
    /// A nested resource is a sub-resource, whose Subject is its path.
    /// For example, a Class might have a nested Property resource with a subject like this:
    /// "https://example.com/someClass https://atomicdata.dev/properties/requires 0"
    nested: Nested<'a>,
}

/// Maps Property URLs to their values
type PropVals = HashMap<String, Value>;

/// Map of nested resources.
/// A path and a SubResource
type Nested<'a> = HashMap<String, Resource<'a>>;

impl<'a> Resource<'a> {
    /// Checks if the classes are there, if not, fetches them
    pub fn get_classes(&mut self) -> AtomicResult<Vec<Class>> {
        if self.classes.is_none() {
            self.classes = Some(self.store.get_classes_for_subject(self.get_subject())?);
        }
        let classes = self.classes.clone().unwrap();
        Ok(classes)
    }

    /// Create a new, empty Resource.
    pub fn new(subject: String, store: &'a dyn Storelike) -> Resource<'a> {
        let propvals: PropVals = HashMap::new();
        let nested: Nested = HashMap::new();
        Resource {
            propvals,
            subject,
            classes: None,
            store,
            nested,
        }
    }

    /// Create a new instance of some Class.
    /// The subject is generated, but can be changed.
    pub fn new_instance(class_url: &str, store: &'a dyn Storelike) -> AtomicResult<Resource<'a>> {
        let propvals: PropVals = HashMap::new();
        let nested: Nested = HashMap::new();
        let mut classes_vec = Vec::new();
        classes_vec.push(store.get_class(class_url)?);
        use rand::Rng;
        let random_string = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(10)
            .collect::<String>();
        let subject = format!(
            "{}/{}/{}",
            store
                .get_base_url()
                .ok_or("No base_url set in this store.")?,
            classes_vec[0].shortname.clone(),
            random_string
        );
        let classes = Some(classes_vec);
        let mut resource = Resource {
            propvals,
            subject,
            classes,
            store,
            nested,
        };
        let class_urls = Vec::from([String::from(class_url)]);
        resource.set_propval(crate::urls::IS_A.into(), class_urls.into())?;
        Ok(resource)
    }

    pub fn new_from_resource_string(
        subject: String,
        resource_string: &ResourceString,
        store: &'a dyn Storelike,
    ) -> AtomicResult<Resource<'a>> {
        let mut res = Resource::new(subject, store);
        for (prop_string, val_string) in resource_string {
            let propertyfull = store.get_property(prop_string).expect("Prop not found");
            let fullvalue = Value::new(val_string, &propertyfull.data_type)?;
            res.set_propval(prop_string.into(), fullvalue)?;
        }
        Ok(res)
    }

    /// Get a value by property URL
    pub fn get(&self, property_url: &str) -> AtomicResult<&Value> {
        Ok(self.propvals.get(property_url).ok_or(format!(
            "Property {} for resource {} not found",
            property_url, self.subject
        ))?)
    }

    /// Gets a value by its shortname
    // Todo: should use both the Classes AND the existing props
    pub fn get_shortname(&self, shortname: &str) -> AtomicResult<&Value> {
        // If there is a class
        for (url, _val) in self.propvals.iter() {
            if let Ok(prop) = self.store.get_property(url) {
                if prop.shortname == shortname {
                    return Ok(self.get(url)?);
                }
            }
        }

        Err("No match".into())
    }

    /// Tries to resolve the shortname to a URL.
    // Currently assumes that classes have been set before.
    pub fn resolve_shortname(&mut self, shortname: &str) -> AtomicResult<Option<Property>> {
        let classes = self.get_classes()?;
        // Loop over all Requires and Recommends props
        for class in classes {
            for required_prop in class.requires {
                if required_prop.shortname == shortname {
                    return Ok(Some(required_prop));
                }
            }
            for recommended_prop in class.recommends {
                if recommended_prop.shortname == shortname {
                    return Ok(Some(recommended_prop));
                }
            }
        }
        Ok(None)
    }

    /// Saves the resource (with all the changes) to the store
    /// Should be called automatically, but we might add some form of batching later
    fn save(&self) -> AtomicResult<()> {
        self.store.add_resource(self)
    }

    /// Insert a Property/Value combination.
    /// Overwrites existing Property/Value.
    /// Validates the datatype.
    pub fn set_propval_string(&mut self, property_url: String, value: &str) -> AtomicResult<()> {
        let fullprop = &self.store.get_property(&property_url)?;
        let val = Value::new(value, &fullprop.data_type)?;
        self.set_propval(property_url, val)?;
        Ok(())
    }

    /// Inserts a Property/Value combination.
    /// Overwrites existing.
    pub fn set_propval(&mut self, property: String, value: Value) -> AtomicResult<()> {
        self.propvals.insert(property, value);
        self.save()?;
        Ok(())
    }

    /// Sets a property / value combination.
    /// Property can be a shortname (e.g. 'description' instead of the full URL), if the Resource has a Class.
    /// Validates the datatype.
    pub fn set_by_shortname(&mut self, property: &str, value: &str) -> AtomicResult<()> {
        let fullprop = if is_url(property) {
            self.store.get_property(property)?
        } else {
            self.resolve_shortname(property)?.unwrap()
        };
        let fullval = Value::new(value, &fullprop.data_type)?;
        self.set_propval(fullprop.subject, fullval)?;
        Ok(())
    }

    pub fn set_subject(&mut self, url: String) {
        self.subject = url;
    }

    pub fn get_subject(&self) -> &String {
        &self.subject
    }

    /// Converts a resource to a string only HashMap
    pub fn to_plain(&self) -> HashMap<String, String> {
        let mut hashmap: HashMap<String, String> = HashMap::new();
        for (prop, val) in &mut self.propvals.clone().into_iter() {
            hashmap.insert(prop, val.to_string());
        }
        hashmap
    }

    // This turned out to be more difficult than I though. I need the full Property, which the Resource does not possess.
    // pub fn to_atoms(&self) -> Vec<RichAtom> {
    //     let mut atoms: Vec<RichAtom> = Vec::new();
    //     for (property, value) in self.propvals.iter() {
    //         let atom = RichAtom::new(self.subject, property, value).unwrap();
    //         atoms.push(value);
    //     }
    //     atoms
    // }
}

/// A plainstring hashmap, which represents a possibly unvalidated Atomic Resource.
/// The key string represents the URL of the Property, the value one its Values.
pub type ResourceString = HashMap<String, String>;

/// Convert a ResourceString to Atoms
pub fn resourcestring_to_atoms(subject: &str, resource: ResourceString) -> Vec<Atom> {
    let mut vec = Vec::new();
    for (prop, val) in resource.iter() {
        vec.push(Atom::new(subject.into(), prop.into(), val.into()));
    }
    vec
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{parse::parse_ad3, urls, Store};

    fn init_store() -> Store {
        let string =
            String::from("[\"_:test\",\"https://atomicdata.dev/properties/shortname\",\"hi\"]");
        let store = Store::init();
        store.populate().unwrap();
        let atoms = parse_ad3(&string).unwrap();
        store.add_atoms(atoms).unwrap();
        store
    }

    #[test]
    fn get_and_set_resource_props() {
        let store = init_store();
        let mut resource = store.get_resource(urls::CLASS).unwrap();
        assert!(resource.get_shortname("shortname").unwrap().to_string() == "class");
        resource
            .set_by_shortname("shortname", "something-valid")
            .unwrap();
        assert!(resource.get_shortname("shortname").unwrap().to_string() == "something-valid");
        resource
            .set_by_shortname("shortname", "should not contain spaces")
            .unwrap_err();
    }

    #[test]
    fn new_instance() {
        let store = init_store();
        let mut new_resource = Resource::new_instance(urls::CLASS, &store).unwrap();
        new_resource.set_by_shortname("shortname", "person").unwrap();
        assert!(new_resource.get_shortname("shortname").unwrap().to_string() == "person");
        new_resource.set_by_shortname("shortname", "human").unwrap();
        assert!(new_resource.get_shortname("shortname").unwrap().to_string() == "human");
        let mut resource_from_store = store.get_resource(new_resource.get_subject()).unwrap();
        assert!(resource_from_store.get_shortname("shortname").unwrap().to_string() == "human");
        println!("{}", resource_from_store.get_shortname("isa").unwrap().to_string());
        assert!(resource_from_store.get_shortname("isa").unwrap().to_string() == r#"["https://atomicdata.dev/classes/Class"]"#);
        assert!(resource_from_store.get_classes().unwrap()[0].shortname == "class");
    }
}
