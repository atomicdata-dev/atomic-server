use crate::errors::AtomicResult;
use crate::urls;
use crate::{
    delta::Delta,
    mapping::Mapping,
    parse::parse_ad3,
    resources::{self, ResourceString},
    values::{match_datatype, DataType, Value},
    Atom, Resource, RichAtom,
};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize)]
pub struct Property {
    // URL of the class
    pub class_type: Option<String>,
    // URL of the datatype
    pub data_type: DataType,
    pub shortname: String,
    pub subject: String,
    pub description: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Class {
    pub requires: Vec<Property>,
    pub recommends: Vec<Property>,
    pub shortname: String,
    pub description: String,
    /// URL
    pub subject: String,
}

// A path can return one of many things
pub enum PathReturn {
    Subject(String),
    Atom(RichAtom),
}

pub type ResourceCollection = Vec<(String, ResourceString)>;

/// Storelike provides many useful methods for interacting with an Atomic Store.
/// It serves as a basic store Trait, agnostic of how it functions under the hood.
/// This is useful, because we can create methods for Storelike that will work with either in-memory
/// stores, as well as with persistend on-disk stores.
pub trait Storelike {
    /// Add individual Atoms to the store.
    /// Will replace existing Atoms that share Subject / Property combination.
    fn add_atoms(&mut self, atoms: Vec<Atom>) -> AtomicResult<()>;

    /// Replaces existing resource with the contents
    /// Accepts a simple nested string only hashmap
    /// Adds to hashmap and to the resource store
    fn add_resource_string(
        &mut self,
        subject: String,
        resource: &ResourceString,
    ) -> AtomicResult<()>;

    /// Returns a hashmap ResourceString with string Values
    fn get_resource_string(&self, resource_url: &str) -> AtomicResult<ResourceString>;

    /// Adds a Resource to the store
    fn add_resource(&mut self, resource: &Resource) -> AtomicResult<()> {
        self.add_resource_string(resource.subject().clone(), &resource.to_plain())?;
        return Ok(());
    }

    /// Fetches a resource, makes sure its subject matches.
    /// Does not save to the store.
    /// Only adds atoms with matching subjects match.
    fn fetch_resource(&self, subject: &str) -> AtomicResult<ResourceString> {
        let resp = ureq::get(&subject)
            .set("Accept", crate::parse::AD3_MIME)
            .call();
        let body = &resp.into_string()?;
        let atoms = parse_ad3(body)?;
        let mut resource = ResourceString::new();
        for atom in atoms {
            if &atom.subject == subject {
                resource.insert(atom.property, atom.value);
            }
        }
        if resource.len() == 0 {
            return Err("No valid atoms in resource".into());
        }
        Ok(resource)
    }

    /// Returns a full Resource with native Values
    fn get_resource(&self, subject: &str) -> AtomicResult<Resource> {
        let resource_string = self.get_resource_string(subject)?;
        let mut res = Resource::new(subject.into());
        for (prop_string, val_string) in resource_string {
            let propertyfull = self.get_property(&prop_string)?;
            let fullvalue =
                Value::new(&val_string, &propertyfull.data_type).expect("Could not convert value");
            res.insert(prop_string.clone(), fullvalue)?;
        }
        Ok(res)
        // Above code is a copy from:
        // let res = Resource::new_from_resource_string(subject.clone(), &resource, self)?;
        // But has some Size issues
    }

    /// Retrieves a Class from the store by subject URL and converts it into a Class useful for forms
    fn get_class(&self, subject: &str) -> AtomicResult<Class> {
        // The string representation of the Class
        let class_strings = self.get_resource_string(subject).expect("Class not found");
        let shortname = class_strings
            .get(urls::SHORTNAME)
            .expect("Class has no shortname");
        let description = class_strings
            .get(urls::DESCRIPTION)
            .expect("Class has no description");
        let requires_string = class_strings.get(urls::REQUIRES);
        let recommends_string = class_strings.get(urls::RECOMMENDS);

        let mut requires: Vec<Property> = Vec::new();
        let mut recommends: Vec<Property> = Vec::new();
        let get_properties = |resource_array: String| -> Vec<Property> {
            let mut properties: Vec<Property> = vec![];
            let string_vec: Vec<String> = crate::parse::parse_json_array(&resource_array).unwrap();
            for prop_url in string_vec {
                properties.push(self.get_property(&prop_url).unwrap());
            }
            return properties;
        };
        if requires_string.is_some() {
            requires = get_properties(requires_string.unwrap().into());
        }
        if recommends_string.is_some() {
            recommends = get_properties(recommends_string.unwrap().into());
        }
        let class = Class {
            requires,
            recommends,
            shortname: shortname.into(),
            subject: subject.into(),
            description: description.into(),
        };

        return Ok(class);
    }

    /// Finds all classes (isA) for any subject.
    /// Returns an empty vector if there are none.
    fn get_classes_for_subject(&self, subject: &String) -> AtomicResult<Vec<Class>> {
        let resource = self.get_resource_string(subject)?;
        let classes_array_opt = resource.get(urls::IS_A);
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
            classes.push(self.get_class(&class)?)
        }
        return Ok(classes);
    }

    /// Fetches a property by URL, returns a Property instance
    fn get_property(&self, url: &str) -> AtomicResult<Property> {
        let property_resource = self.get_resource_string(url)?;
        let property = Property {
            data_type: match_datatype(
                &property_resource
                    .get(urls::DATATYPE_PROP)
                    .ok_or(format!("Datatype not found for property {}", url))?,
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

    /// Returns a collection with all resources in the store.
    /// WARNING: This could be very expensive!
    fn all_resources(&self) -> AtomicResult<ResourceCollection>;

    /// Adds an atom to the store. Does not do any validations
    fn add_atom(&mut self, atom: Atom) -> AtomicResult<()> {
        match self.get_resource_string(&atom.subject).as_mut() {
            Ok(resource) => {
                // Overwrites existing properties
                match resource.insert(atom.property, atom.value) {
                    Some(_oldval) => {
                        // Remove the value from the Subject index
                        // self.index_value_remove(atom);
                    }
                    None => {}
                };
                self.add_resource_string(atom.subject, &resource)?;
            }
            Err(_) => {
                let mut resource: ResourceString = HashMap::new();
                resource.insert(atom.property, atom.value);
                self.add_resource_string(atom.subject, &resource)?;
            }
        };
        Ok(())
    }

    /// Processes a vector of deltas and updates the store.
    /// Panics if the
    /// Use this for ALL updates to the store!
    fn process_delta(&mut self, delta: Delta) -> AtomicResult<()> {
        let mut updated_resources = Vec::new();

        for delta in delta.lines.iter() {
            match delta.method.as_str() {
                urls::INSERT | "insert" => {
                    let datatype = self
                        .get_property(&delta.property)
                        .expect("Can't get property")
                        .data_type;
                    Value::new(&delta.value, &datatype)?;
                    updated_resources.push(&delta.subject);
                    self.add_atom(Atom::from(delta))?;
                }
                urls::DELETE | "delete" => {
                    self.add_atom(Atom::from(delta))?;
                }
                unknown => println!("Ignoring unknown method: {}", unknown),
            };
        }
        Ok(())
    }

    /// Finds the URL of a shortname used in the context of a specific Resource.
    /// The Class, Properties and Shortnames of the Resource are used to find this URL
    fn property_shortname_to_url(
        &self,
        shortname: &str,
        resource: &ResourceString,
    ) -> AtomicResult<String> {
        for (prop_url, _value) in resource.iter() {
            let prop_resource = self.get_resource_string(&*prop_url)?;
            let prop_shortname = prop_resource
                .get(urls::SHORTNAME)
                .ok_or(format!("Property shortname for '{}' not found", prop_url))?;
            if prop_shortname == shortname {
                return Ok(prop_url.clone());
            }
        }
        return Err(format!("Could not find shortname {}", shortname).into());
    }

    /// Finds
    fn property_url_to_shortname(&self, url: &String) -> AtomicResult<String> {
        let resource = self.get_resource_string(url)?;
        let property_resource = resource
            .get(urls::SHORTNAME)
            .ok_or(format!("Could not get shortname prop for {}", url))?;

        return Ok(property_resource.into());
    }

    /// fetches a resource, serializes it to .ad3
    /// The local_base_url is needed to convert the local identifier to the domain
    /// It should be something like `https://example.com/`
    fn resource_to_ad3(
        &self,
        subject: &String,
        local_base_url: Option<&String>,
    ) -> AtomicResult<String> {
        let mut string = String::new();
        let resource = self.get_resource_string(subject)?;
        let mut mod_subject = subject.clone();
        // Replace local schema with actual local domain
        if subject.starts_with("_:") && local_base_url.is_some() {
            // Remove first two characters
            let mut chars = subject.chars();
            chars.next();
            chars.next();
            mod_subject = format!("{}{}", &local_base_url.unwrap(), &chars.as_str());
        }
        for (property, value) in resource {
            let mut ad3_atom = serde_json::to_string(&vec![&mod_subject, &property, &value])
                .expect("Can't serialize");
            ad3_atom.push_str("\n");
            &string.push_str(&*ad3_atom);
        }
        return Ok(string);
    }

    /// Serializes a single Resource to a JSON object.
    /// It uses the Shortnames of properties for Keys.
    /// The depth is useful, since atomic data allows for cyclical (infinite-depth) relationships
    // Very naive implementation, should actually turn:
    // [x] ResourceArrays into arrrays
    // [x] URLS into @id things
    // [x] Numbers into native numbers
    // [ ] Resoures into objects, if the nesting depth allows it
    fn resource_to_json(
        &self,
        resource_url: &String,
        _depth: u32,
        json_ld: bool,
    ) -> AtomicResult<String> {
        use serde_json::{Map, Value as SerdeValue};

        let resource = self.get_resource_string(resource_url)?;

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
            let native_value = Value::new(value, &property.data_type).expect(&*format!(
                "Could not convert value {:?} with property type {:?} into native value",
                value, &property.data_type
            ));
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

    /// Triple Pattern Fragments interface.
    /// Use this for most queries, e.g. finding all items with some property / value combination.
    /// Returns an empty array if nothing is found.
    ///
    /// # Example
    ///
    /// For example, if I want to view all Resources that are instances of the class "Property", I'd do:
    ///
    /// ```
    /// use atomic_lib::Storelike;
    /// let mut store = atomic_lib::Store::init();
    /// store.populate();
    /// let atoms = store.tpf(
    ///     None,
    ///     Some("https://atomicdata.dev/properties/isA"),
    ///     Some("[\"https://atomicdata.dev/classes/Class\"]")
    /// ).unwrap();
    /// assert!(atoms.len() == 3)
    /// ```
    // Very costly, slow implementation.
    // Does not assume any indexing.
    fn tpf(
        &self,
        q_subject: Option<&str>,
        q_property: Option<&str>,
        q_value: Option<&str>,
    ) -> AtomicResult<Vec<Atom>> {
        let mut vec: Vec<Atom> = Vec::new();

        let hassub = q_subject.is_some();
        let hasprop = q_property.is_some();
        let hasval = q_value.is_some();

        // Simply return all the atoms
        if !hassub && !hasprop && !hasval {
            for (sub, resource) in self.all_resources()? {
                for (property, value) in resource {
                    vec.push(Atom::new(&sub, &property, &value))
                }
            }
            return Ok(vec);
        }

        // Find atoms matching the TPF query in a single resource
        let mut find_in_resource = |subj: &str, resource: &ResourceString| {
            for (prop, val) in resource.iter() {
                if hasprop && q_property.as_ref().unwrap() == prop {
                    if hasval {
                        if val == q_value.as_ref().unwrap() {
                            vec.push(Atom::new(subj, prop, val))
                        }
                    } else {
                        vec.push(Atom::new(subj, prop, val))
                    }
                } else if hasval && q_value.as_ref().unwrap() == val {
                    vec.push(Atom::new(subj, prop, val))
                }
            }
        };

        match q_subject {
            Some(sub) => match self.get_resource_string(&sub) {
                Ok(resource) => {
                    if q_property.is_some() | q_value.is_some() {
                        find_in_resource(&sub, &resource);
                        return Ok(vec);
                    } else {
                        return Ok(resources::resourcestring_to_atoms(sub, resource));
                    }
                }
                Err(_) => {
                    return Ok(vec);
                }
            },
            None => {
                for (subj, properties) in self.all_resources()? {
                    find_in_resource(&subj, &properties);
                }
                return Ok(vec);
            }
        }
    }

    /// Accepts an Atomic Path string, returns the result value (resource or property value)
    /// E.g. `https://example.com description` or `thing isa 0`
    /// https://docs.atomicdata.dev/core/paths.html
    //  Todo: return something more useful, give more context.
    fn get_path(&self, atomic_path: &str, mapping: &Mapping) -> AtomicResult<PathReturn> {
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
        let mut resource = self.get_resource_string(&subject)?;
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
                        // let resource_check = resource.ok_or("Resource not found")?;
                        let array_string = resource
                            .get(&atom.property.subject)
                            .ok_or(format!("Property {} not found", &atom.property.subject))?;
                        let vector: Vec<String> = crate::parse::parse_json_array(array_string)
                            .expect(&*format!("Failed to parse array: {}", array_string));
                        if vector.len() <= i as usize {
                            eprintln!(
                                "Too high index ({}) for array with length {}",
                                i,
                                array_string.len()
                            );
                        }
                        let url = &vector[i as usize];
                        subject = url.into();
                        resource = self.get_resource_string(&subject)?;
                        current = PathReturn::Subject(subject.clone().into());
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
            if crate::mapping::is_url(&String::from(item)) {
                property_url = Some(String::from(item));
            } else {
                // Traverse relations, don't use mapping here, but do use classes
                property_url =
                    Some(self.property_shortname_to_url(&String::from(item), &resource.clone())?);
            }
            // Set the parent for the next loop equal to the next node.
            let value = Some(
                resource
                    .clone()
                    .get(&property_url.clone().unwrap())
                    .unwrap()
                    .clone(),
            );
            current = PathReturn::Atom(RichAtom::new(
                subject.clone(),
                self.get_property(&property_url.clone().unwrap()).unwrap(),
                value.clone().unwrap().clone(),
            )?)
        }
        return Ok(current);
    }

    /// Checks Atomic Data in the store for validity.
    /// Returns an Error if it is not valid.
    ///
    /// Validates:
    ///
    /// - [X] If the Values can be parsed using their Datatype (e.g. if Integers are integers)
    /// - [X] If all required fields of the class are present
    /// - [ ] If the URLs are publicly accessible and return the right type of data
    /// - [ ] Returns a report, instead of throws an error
    #[allow(dead_code, unreachable_code)]
    fn validate_store(&self) -> AtomicResult<()> {
        for (subject, resource) in self.all_resources()? {
            println!("Subject: {:?}", subject);
            println!("Resource: {:?}", resource);

            let mut found_props: Vec<String> = Vec::new();

            for (prop_url, value) in resource {
                let property = self.get_property(&prop_url)?;

                Value::new(&value, &property.data_type)?;
                found_props.push(prop_url.clone());
                // println!("{:?}: {:?}", prop_url, value);
            }
            let classes = self.get_classes_for_subject(&subject)?;
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

    /// Loads the default store
    fn populate(&mut self) -> AtomicResult<()> {
        let ad3 = include_str!("../defaults/default_store.ad3");
        let atoms = crate::parse::parse_ad3(&String::from(ad3))?;
        self.add_atoms(atoms)?;
        Ok(())
    }
}
