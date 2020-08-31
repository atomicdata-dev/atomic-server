//! Store - this is an in-memory store of Atomic data.
//! This provides many methods for finding, changing, serializing and parsing Atomic Data.
//! Currently, it can only persist its data as .ad3 (Atomic Data Triples) to disk.
//! A more robust persistent storage option will be used later, such as: https://github.com/TheNeikos/rustbreak

use crate::errors::Result;
use crate::mapping;
use crate::mutations;
use crate::values::{DataType, Value, match_datatype};
use crate::{atoms::{RichAtom, Atom}, urls, storelike::{Property, Storelike, Class, ResourceString}};
use mapping::Mapping;
use serde_json::from_str;
use std::{collections::HashMap, fs, path::PathBuf};

/// The in-memory store of data, containing the Resources, Properties and Classes
#[derive(Clone)]
pub struct Store {
    // The store currently holds two stores - that is not ideal
    hashmap: HashMap<String, ResourceString>,
    log: mutations::Log,
}

impl Store {
    /// Create an empty Store. This is where you start.
    ///
    /// # Example
    /// let store = Store::init();
    pub fn init() -> Store {
        return Store {
            hashmap: HashMap::new(),
            log: Vec::new(),
        };
    }

    /// Add individual Atoms to the store.
    /// Will replace existing Atoms that share Subject / Property combination.
    pub fn add_atoms(&mut self, atoms: Vec<Atom>) -> Result<()> {
        for atom in atoms {
            match self.hashmap.get_mut(&atom.subject) {
                Some(resource) => {
                    resource
                        .insert(atom.property, atom.value)
                        .ok_or(&*format!("Failed to add atom"))?;
                }
                None => {
                    let mut resource: ResourceString = HashMap::new();
                    resource.insert(atom.property, atom.value);
                    self.hashmap.insert(atom.subject, resource);
                }
            }
        }
        return Ok(());
    }

    /// Replaces existing resource with the contents
    /// Accepts a simple nested string only hashmap
    /// Adds to hashmap and to the resource store
    pub fn add_resource(&mut self, subject: String, resource: ResourceString) -> Result<()> {
        self.hashmap.insert(subject.clone(), resource.clone());
        return Ok(());
    }

    /// Parses an Atomic Data Triples (.ad3) string and adds the Atoms to the store.
    /// Allows comments and empty lines.
    pub fn parse_ad3<'a, 'b>(&mut self, string: &'b String) -> Result<()> {
        let mut atoms: Vec<Atom> = Vec::new();
        for line in string.lines() {
            match line.chars().next() {
                // These are comments
                Some('#') => {}
                Some(' ') => {}
                // That's an array, awesome
                Some('[') => {
                    let string_vec: Vec<String> =
                        from_str(line).expect(&*format!("Parsing error in {:?}", line));
                    if string_vec.len() != 3 {
                        return Err(format!("Wrong length of array at line {:?}: wrong length of array, should be 3", line).into());
                    }
                    let subject = &string_vec[0];
                    let property = &string_vec[1];
                    let value = &string_vec[2];
                    atoms.push(Atom::new(subject.clone(), property.clone(), value.clone()));
                }
                Some(char) => {
                    return Err(
                        format!("Parsing error at {:?}, cannot start with {}", line, char).into(),
                    )
                }
                None => {}
            };
        }
        self.add_atoms(atoms)?;
        return Ok(());
    }

    /// Reads an .ad3 (Atomic Data Triples) graph and adds it to the store
    pub fn read_store_from_file<'a>(&mut self, path: &'a PathBuf) -> Result<()> {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                self.parse_ad3(&contents)?;
                Ok(())
            }
            Err(err) => Err(format!("Parsing error: {}", err).into()),
        }
    }

    /// Serializes the current store and saves to path
    pub fn write_store_to_disk(&self, path: &PathBuf) -> Result<()> {
        let mut file_string: String = String::new();
        for (subject, _) in self.hashmap.iter() {
            let resourcestring = self.resource_to_ad3(&subject, None)?;
            &file_string.push_str(&*resourcestring);
        }
        fs::create_dir_all(path.parent().expect("Could not find parent folder"))
            .expect("Unable to create dirs");
        fs::write(path, file_string).expect("Unable to write file");
        return Ok(());
    }

    /// Serializes a single Resource to a JSON object.
    /// It uses the Shortnames of properties for Keys.
    /// The depth is useful, since atomic data allows for cyclical (infinite-depth) relationships
    // Very naive implementation, should actually turn:
    // [x] ResourceArrays into arrrays
    // [x] URLS into @id things
    // [ ] Numbers into native numbers
    // [ ] Resoures into objects, if the nesting depth allows it
    pub fn resource_to_json(
        &self,
        resource_url: &String,
        _depth: u32
    ) -> Result<String> {
        use serde_json::{Map, Value as SerdeValue};

        let json_ld: bool = false;

        let resource = self.get_string_resource(resource_url).ok_or("Resource not found")?;

        // Initiate JSON object
        let mut root = Map::new();

        // For JSON-LD serialization
        let mut context = Map::new();

        // For every atom, find the key, datatype and add it to the @context
        for (prop_url, value) in resource.iter() {
            // We need the Property for shortname and Datatype
            let property = self.get_property(prop_url)?;
            if json_ld {
                // In JSON-LD, the value of a Context Item can be a string or an object.
                // This object can contain information about the translation or datatype of the value
                let ctx_value: SerdeValue = match property.data_type {
                    DataType::AtomicUrl => {
                        let mut obj = Map::new();
                        obj.insert("@id".into(), prop_url.as_str().into());
                        obj.insert("@type".into(), "@id".into());
                        obj.into()
                    }
                    DataType::Date => {
                        let mut obj = Map::new();
                        obj.insert("@id".into(), prop_url.as_str().into());
                        obj.insert(
                            "@type".into(),
                            "http://www.w3.org/2001/XMLSchema#date".into(),
                        );
                        obj.into()
                    }
                    DataType::Integer => {
                        let mut obj = Map::new();
                        obj.insert("@id".into(), prop_url.as_str().into());
                        // I'm not sure whether we should use XSD or Atomic Datatypes
                        obj.insert(
                            "@type".into(),
                            "http://www.w3.org/2001/XMLSchema#integer".into(),
                        );
                        obj.into()
                    }
                    DataType::Markdown => prop_url.as_str().into(),
                    DataType::ResourceArray => {
                        let mut obj = Map::new();
                        obj.insert("@id".into(), prop_url.as_str().into());
                        // Plain JSON-LD Arrays are not ordered. Here, they are converted into an RDF List.
                        obj.insert("@container".into(), "@list".into());
                        obj.into()
                    }
                    DataType::Slug => prop_url.as_str().into(),
                    DataType::String => prop_url.as_str().into(),
                    DataType::Timestamp => prop_url.as_str().into(),
                    DataType::Unsupported(_) => prop_url.as_str().into(),
                };
                context.insert(property.shortname.as_str().into(), ctx_value);
            }
            let native_value = Value::new(value, &property.data_type)
                .expect(&*format!(
                    "Could not convert value {:?} with property type {:?} into native value",
                    value,
                    &property.data_type)
                );
            let jsonval = match native_value {
                Value::AtomicUrl(val) => SerdeValue::String(val.into()),
                Value::Date(val) => SerdeValue::String(val.into()),
                Value::Integer(val) => SerdeValue::Number(val.into()),
                Value::Markdown(val) => SerdeValue::String(val.into()),
                Value::ResourceArray(val) => SerdeValue::Array(
                    val.iter()
                        .map(|item| SerdeValue::String(item.clone()))
                        .collect(),
                ),
                Value::Slug(val) => SerdeValue::String(val.into()),
                Value::String(val) => SerdeValue::String(val.into()),
                Value::Timestamp(val) => SerdeValue::Number(val.into()),
                Value::Unsupported(val) => SerdeValue::String(val.value.into()),
            };
            root.insert(property.shortname, jsonval);
        }

        if json_ld {
            root.insert("@context".into(), context.into());
            root.insert("@id".into(), resource_url.as_str().into());
        }
        let obj = SerdeValue::Object(root);
        let string = serde_json::to_string_pretty(&obj).expect("Could not serialize to JSON");

        return Ok(string);
    }

    /// Fetches a property by URL, returns a Property instance
    pub fn get_property(&self, url: &String) -> Result<Property> {
        let property_resource = self
            .hashmap
            .get(url)
            .ok_or(&*format!("Property not found: {}", url))?;
        let property = Property {
            data_type: match_datatype(
                property_resource
                    .get(urls::DATATYPE_PROP)
                    .ok_or(format!("Datatype not found for property {}", url))?
                    .into(),
            ),
            shortname: property_resource
                .get(urls::SHORTNAME)
                .ok_or(format!("Shortname not found for property {}", url))?
                .into(),
            description: property_resource
                .get(urls::DESCRIPTION)
                .ok_or(format!("Description not found for property {}", url))?
                .into(),
            class_type: property_resource
                .get(urls::CLASSTYPE_PROP)
                .map(|s| s.clone()),
            subject: url.into(),
        };

        return Ok(property);
    }

    /// Finds all classes (isA) for any subject.
    /// Returns an empty vector if there are none.
    pub fn get_classes_for_subject(&self, subject: &String) -> Result<Vec<Class>> {
        let resource = self
            .get_string_resource(subject)
            .ok_or(format!("Subject not found: {}", subject))?;
        let classes_array_opt = resource
            .get(urls::IS_A);
        let classes_array = match classes_array_opt {
            Some(vec) => vec,
            None => return Ok(Vec::new()),
        };
        // .ok_or(format!("IsA property not present in {}", subject))?;
        let native = Value::new(classes_array, &DataType::ResourceArray)?;
        let vector = match native {
            Value::ResourceArray(vec) => vec,
            _ => return Err("Should be an array".into()),
        };
        let mut classes: Vec<Class> = Vec::new();
        for class in vector {
            classes.push(self.get_class(&class))
        }
        return Ok(classes);
    }

    pub fn property_url_to_shortname(&self, url: &String) -> Result<String> {
        let property_resource = self
            .hashmap
            .get(url)
            .ok_or(format!("Could not find property for {}", url))?
            .get(urls::SHORTNAME)
            .ok_or(format!("Could not get shortname prop for {}", url))?;

        return Ok(property_resource.into());
    }

    /// Accepts an Atomic Path string, returns the result value (resource or property value)
    /// https://docs.atomicdata.dev/core/paths.html
    //  Todo: return something more useful, give more context.
    pub fn get_path(&self, atomic_path: &str, mapping: &Mapping) -> Result<PathReturn> {
        // The first item of the path represents the starting Resource, the following ones are traversing the graph / selecting properties.
        let path_items: Vec<&str> = atomic_path.split(' ').collect();
        // For the first item, check the user mapping
        let id_url: String = mapping
            .try_mapping_or_url(&String::from(path_items[0]))
            .ok_or(&*format!("No url found for {}", path_items[0]))?;
        if path_items.len() == 1 {
            return Ok(PathReturn::Subject(id_url));
        }
        // The URL of the next resource
        let mut subject = id_url;
        // Set the currently selectred resource parent, which starts as the root of the search
        let mut resource: Option<&ResourceString> = self.hashmap.get(&subject);
        // During each of the iterations of the loop, the scope changes.
        // Try using pathreturn...
        let mut current: PathReturn = PathReturn::Subject(subject.clone());
        // Loops over every item in the list, traverses the graph
        // Skip the first one, for that is the subject (i.e. first parent) and not a property
        for item in path_items[1..].iter().cloned() {
            // In every iteration, the subject, property_url and current should be set.
            // Ignore double spaces
            if item == "" {
                continue;
            }
            // If the item is a number, assume its indexing some array
            match item.parse::<u32>() {
                Ok(i) => match current {
                    PathReturn::Atom(atom) => {
                        let array_string = resource
                            .ok_or("Resource not found")?
                            .get(&atom.property.subject)
                            .ok_or("Property not found")?;
                        let vector: Vec<String> =
                            from_str(array_string).expect("Failed to parse array");
                        if vector.len() <= i as usize {
                            eprintln!(
                                "Too high index ({}) for array with length {}",
                                i,
                                array_string.len()
                            );
                        }
                        let url = &vector[i as usize];

                        subject = url.clone();
                        resource = self.hashmap.get(url);
                        current = PathReturn::Subject(url.clone());
                        continue;
                    }
                    PathReturn::Subject(_) => {
                        return Err("You can't do an index on a resource, only on arrays.".into())
                    }
                },
                Err(_) => {}
            };
            // Since the selector isn't an array index, we can assume it's a property URL
            let property_url;
            // Get the shortname or use the URL
            if mapping::is_url(&String::from(item)) {
                property_url = Some(String::from(item));
            } else {
                // Traverse relations, don't use mapping here, but do use classes
                property_url = Some(self.property_shortname_to_url(
                    &String::from(item),
                    resource.ok_or("Relation not found")?,
                )?);
            }
            // Set the parent for the next loop equal to the next node.
            let value = Some(
                resource
                    .expect("Resource not found")
                    .get(&property_url.clone().unwrap())
                    .unwrap()
                    .clone(),
            );
            current = PathReturn::Atom(RichAtom::new(
                subject.clone(),
                property_url.clone().unwrap(),
                value.clone().unwrap(),
                &self,
            ))
        }
        return Ok(current);
    }

    /// Finds the URL of a shortname used in the context of a specific Resource.
    /// The Class, Properties and Shortnames of the Resource are used to find this URL
    pub fn property_shortname_to_url(
        &self,
        shortname: &String,
        resource: &ResourceString,
    ) -> Result<String> {
        for (prop_url, _value) in resource.iter() {
            let prop_resource = self
                .hashmap
                .get(&*prop_url)
                .ok_or(format!("Property '{}' not found", prop_url))?;
            let prop_shortname = prop_resource
                .get(urls::SHORTNAME)
                .ok_or(format!("Property shortname for '{}' not found", prop_url))?;
            if prop_shortname == shortname {
                return Ok(prop_url.clone());
            }
        }
        return Err(format!("Could not find shortname {}", shortname).into());
    }

    /// Gets a resource where with Values instead of strings
    pub fn get_native(&self) {}

    // Returns an enum of the native value.
    // Validates the contents.
    pub fn get_native_value(value: &String, datatype: &DataType) -> Result<Value> {
        Value::new(value, datatype)
    }

    pub fn resource_to_ad3(&self, subject: &String, domain: Option<&String>) -> Result<String> {
        let mut string = String::new();
        let resource = self.get_string_resource(subject).ok_or("Resource not found")?;
        let mut mod_subject = subject.clone();
        // Replace local schema with actual local domain
        if subject.starts_with("_:") && domain.is_some() {
            // Remove first two characters
            let mut chars = subject.chars();
            chars.next();
            chars.next();
            mod_subject = format!("{}{}", &domain.unwrap(), &chars.as_str());
        }
        for (property, value) in resource {
            let mut ad3_atom = serde_json::to_string(&vec![&mod_subject, &property, &value])
                .expect("Can't serialize");
            ad3_atom.push_str("\n");
            &string.push_str(&*ad3_atom);
        }
        return Ok(string);
    }

    /// Checks Atomic Data in the store for validity.
    /// Returns an Error if it is not valid.
    ///
    /// Validates:
    ///
    /// - [X] If the Values can be parsed using their Datatype (e.g. if Integers are integers)
    /// - [X] If all required fields of the class are present
    /// - [ ] If the URLs are publicly accessible and return the right type of data
    /// - [ ] Returns a report with multiple options
    #[allow(dead_code, unreachable_code)]
    pub fn validate_store(&self) -> Result<()> {
        for (subject, resource) in self.hashmap.iter() {
            println!("Subject: {:?}", subject);
            println!("Resource: {:?}", resource);

            let mut found_props: Vec<String> = Vec::new();

            for (prop_url, value) in resource {
                let property = self.get_property(prop_url)?;

                Value::new(value, &property.data_type)?;
                found_props.push(prop_url.clone());
                // println!("{:?}: {:?}", prop_url, value);
            }
            let classes = self.get_classes_for_subject(subject)?;
            for class in classes {
                println!("Class: {:?}", class.shortname);
                println!("Found: {:?}", found_props);
                for required_prop in class.requires {
                    println!("Required: {:?}", required_prop.shortname);
                    if !found_props.contains(&required_prop.subject) {
                        return Err(format!(
                            "Missing requried property {} in {} because of class {}",
                            &required_prop.shortname, subject, class.subject,
                        )
                        .into());
                    }
                }
            }
            println!("{:?} Valid", subject);
        }
        return Ok(());
    }

    /// Triple Pattern Fragments interface.
    /// Use this for most queries, e.g. finding all items with some property / value combination.
    /// Returns an empty array if nothing is found.
    ///
    /// # Example
    ///
    /// For example, if I want to view all Resources that are instances of the class "Property", I'd do:
    ///
    /// ```
    /// let mut store = atomic_lib::Store::init();
    /// store.load_default();
    /// let atoms = store.tpf(
    ///     None,
    ///     Some(String::from("https://atomicdata.dev/properties/isA")),
    ///     Some(String::from("[\"https://atomicdata.dev/classes/Class\"]"))
    /// );
    /// assert!(atoms.len() == 3)
    /// ```
    pub fn tpf(
        &self,
        q_subject: Option<String>,
        q_property: Option<String>,
        q_value: Option<String>,
    ) -> Vec<Atom> {
        let mut vec: Vec<Atom> = Vec::new();

        let hassub = q_subject.is_some();
        let hasprop = q_property.is_some();
        let hasval = q_value.is_some();

        // Simply return all the atoms
        if !hassub && !hasprop && !hasval {
            for (sub, resource) in self.hashmap.iter() {
                for (property, value) in resource {
                    vec.push(Atom::new(sub.into(), property.into(), value.into()))
                }
            }
            return vec;
        }

        // Find atoms matching the TPF query in a single resource
        let mut find_in_resource = |subj: &String, resource: &ResourceString| {
            for (prop, val) in resource.iter() {
                if hasprop && q_property.as_ref().unwrap() == prop {
                        if hasval {
                        if val == q_value.as_ref().unwrap() {
                            vec.push(Atom::new(subj.into(), prop.into(), val.into()))
                        }
                    } else {
                        vec.push(Atom::new(subj.into(), prop.into(), val.into()))
                    }
                } else if hasval && q_value.as_ref().unwrap() == val {
                    vec.push(Atom::new(subj.into(), prop.into(), val.into()))
                }
            }
        };

        match q_subject {
            Some(sub) => match self.get_string_resource(&sub) {
                Some(resource) => {
                    find_in_resource(&sub, &resource);
                    return vec;
                }
                None => {
                    return vec;
                }
            },
            None => {
                for (subj, properties) in self.hashmap.iter() {
                    find_in_resource(subj, properties);
                }
                return vec;
            }
        }
    }

    /// Loads the default Atomic Store, containing the Properties, Datatypes and Clasess for Atomic Schema.
    pub fn load_default(&mut self) {
        let ad3 = include_str!("../../defaults/default_store.ad3");
        self.parse_ad3(&String::from(ad3)).unwrap();
    }
}

impl Storelike for Store {
    fn get_string_resource(&self, resource_url: &String) -> Option<ResourceString> {
        match self.hashmap.get(resource_url) {
            Some(result) => Some(result.clone()),
            None => None
        }
    }
}

// A path can return one of many things
pub enum PathReturn {
    Subject(String),
    Atom(RichAtom),
}

#[cfg(test)]
mod test {
    use super::*;

    fn init_store() -> Store {
        let string =
            String::from("[\"_:test\",\"https://atomicdata.dev/properties/shortname\",\"hi\"]");
        let mut store = Store::init();
        store.load_default();
        // Run parse...
        store.parse_ad3(&string).unwrap();
        return store;
    }

    #[test]
    fn get() {
        let store = init_store();
        // Get our resource...
        let my_resource = store.get_string_resource(&"_:test".into()).unwrap();
        // Get our value by filtering on our property...
        let my_value = my_resource
            .get("https://atomicdata.dev/properties/shortname")
            .unwrap();
        println!("My value: {}", my_value);
        assert!(my_value == "hi");
    }

    #[test]
    fn validate() {
        let store = init_store();
        store.validate_store().unwrap();
    }

    #[test]
    #[should_panic]
    fn validate_invalid() {
        let mut store = init_store();
        let invalid_ad3 =
            // should be array, is string
            String::from("[\"_:test\",\"https://atomicdata.dev/properties/requires\",\"Test\"]");
        store.parse_ad3(&invalid_ad3).unwrap();
        store.validate_store().unwrap();
    }

    #[test]
    fn serialize() {
        let store = init_store();
        store.resource_to_json(
            &String::from(urls::CLASS),
            1
        ).unwrap();
    }
}
