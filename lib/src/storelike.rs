use crate::errors::AtomicResult;
use crate::urls;
use crate::{
    values::{match_datatype, DataType, Value},
    Atom, mapping::Mapping, RichAtom,
};
use serde::Serialize;
use std::collections::HashMap;

/// The first string represents the URL of the Property, the second one its Value.
pub type ResourceString = HashMap<String, String>;

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

#[derive(Debug)]
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

/// Storelike provides many useful methods for interacting with an Atomic Store.
/// It serves as a basic store Trait, agnostic of how it functions under the hood.
/// This is useful, because we can create methods for Storelike that will work with either in-memory
/// stores, as well as with persistend on-disk stores.
pub trait Storelike {
    /// Add individual Atoms to the store.
    /// Will replace existing Atoms that share Subject / Property combination.
    fn add_atoms(&mut self, atoms: Vec<Atom>) -> AtomicResult<()>;

    fn get_string_resource(&self, resource_url: &String) -> Option<ResourceString>;

    /// Retrieves a Class from the store by subject URL and converts it into a Class useful for forms
    fn get_class(&self, subject: &String) -> Class {
        // The string representation of the Class
        let class_strings = self.get_string_resource(&subject).expect("Class not found");
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
            let string_vec: Vec<String> =
                crate::serialize::deserialize_json_array(&resource_array.into()).unwrap();
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

        return class;
    }

    /// Finds all classes (isA) for any subject.
    /// Returns an empty vector if there are none.
    fn get_classes_for_subject(&self, subject: &String) -> AtomicResult<Vec<Class>> {
        let resource = self
            .get_string_resource(subject)
            .ok_or(format!("Subject not found: {}", subject))?;
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
            classes.push(self.get_class(&class))
        }
        return Ok(classes);
    }

    /// Fetches a property by URL, returns a Property instance
    fn get_property(&self, url: &String) -> AtomicResult<Property> {
        let property_resource = self
            .get_string_resource(url)
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

    /// Finds the URL of a shortname used in the context of a specific Resource.
    /// The Class, Properties and Shortnames of the Resource are used to find this URL
    fn property_shortname_to_url(
        &self,
        shortname: &String,
        resource: &ResourceString,
    ) -> AtomicResult<String> {
        for (prop_url, _value) in resource.iter() {
            let prop_resource = self
                .get_string_resource(&*prop_url)
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

    /// Finds
    fn property_url_to_shortname(&self, url: &String) -> AtomicResult<String> {
        let resource = self
            .get_string_resource(url)
            .ok_or(format!("Could not find property for {}", url))?;
        let property_resource = resource
            .get(urls::SHORTNAME)
            .ok_or(format!("Could not get shortname prop for {}", url))?;

        return Ok(property_resource.into());
    }

    fn resource_to_ad3(&self, subject: &String, domain: Option<&String>) -> AtomicResult<String> {
        let mut string = String::new();
        let resource = self
            .get_string_resource(subject)
            .ok_or("Resource not found")?;
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

    /// Serializes a single Resource to a JSON object.
    /// It uses the Shortnames of properties for Keys.
    /// The depth is useful, since atomic data allows for cyclical (infinite-depth) relationships
    // Very naive implementation, should actually turn:
    // [x] ResourceArrays into arrrays
    // [x] URLS into @id things
    // [ ] Numbers into native numbers
    // [ ] Resoures into objects, if the nesting depth allows it
    fn resource_to_json(&self, resource_url: &String, _depth: u32) -> AtomicResult<String> {
        use serde_json::{Map, Value as SerdeValue};

        let json_ld: bool = false;

        let resource = self
            .get_string_resource(resource_url)
            .ok_or("Resource not found")?;

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
    /// let mut store = atomic_lib::Store::init();
    /// store.load_default();
    /// let atoms = store.tpf(
    ///     None,
    ///     Some(String::from("https://atomicdata.dev/properties/isA")),
    ///     Some(String::from("[\"https://atomicdata.dev/classes/Class\"]"))
    /// );
    /// assert!(atoms.len() == 3)
    /// ```
    fn tpf(
        &self,
        q_subject: Option<String>,
        q_property: Option<String>,
        q_value: Option<String>,
    ) -> Vec<Atom>;

    /// Accepts an Atomic Path string, returns the result value (resource or property value)
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
        let mut resource: Option<ResourceString> = self.get_string_resource(&subject);
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
                        let resource_check = resource.ok_or("Resource not found")?;
                        let array_string = resource_check
                            .get(&atom.property.subject)
                            .ok_or("Property not found")?;
                        let vector: Vec<String> =
                            crate::serialize::deserialize_json_array(array_string).expect("Failed to parse array");
                        if vector.len() <= i as usize {
                            eprintln!(
                                "Too high index ({}) for array with length {}",
                                i,
                                array_string.len()
                            );
                        }
                        let url = &vector[i as usize];

                        subject = url.clone();
                        resource = self.get_string_resource(url);
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
            if crate::mapping::is_url(&String::from(item)) {
                property_url = Some(String::from(item));
            } else {
                // Traverse relations, don't use mapping here, but do use classes
                property_url = Some(self.property_shortname_to_url(
                    &String::from(item),
                    &resource.clone().ok_or("Relation not found")?,
                )?);
            }
            // Set the parent for the next loop equal to the next node.
            let value = Some(
                resource
                    .clone()
                    .expect("Resource not found")
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
}
