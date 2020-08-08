// Store - this is an in-memory store of Atomic data.
// Currently, it writes everything as .ad3 (NDJSON arrays) to disk, but this should change later on.
// Perhaps we'll use some database, or something very specific to rust: https://github.com/TheNeikos/rustbreak

use crate::errors::Result;
use crate::mapping;
use crate::{serialize, serialize::deserialize_json_array, urls, atom::Atom};
use mapping::Mapping;
use regex::Regex;
use serde::Serialize;
use serde_json::from_str;
use std::{collections::HashMap, fs, path::PathBuf};

/// The first string represents the URL of the Property, the second one its Value.
pub type Resource = HashMap<String, String>;

#[derive(Serialize)]
pub struct Property {
    // URL of the class
    pub class_type: Option<String>,
    // URL of the datatype
    pub data_type: DataType,
    pub shortname: String,
    pub subject: String,
    pub description: String,
}

#[derive(Debug, Serialize)]
pub enum DataType {
    AtomicUrl,
    Date,
    Integer,
    MDString,
    ResourceArray,
    Slug,
    String,
    Timestamp,
    Unsupported(String),
}

#[derive(Debug)]
pub enum Value {
    AtomicUrl(String),
    Date(String),
    Integer(i32),
    MDString(String),
    ResourceArray(Vec<String>),
    Slug(String),
    String(String),
    Timestamp(i64),
    UnkownValue(UnkownValue),
}

#[derive(Debug)]
pub struct UnkownValue {
    pub value: String,
    // URL of the datatype
    pub datatype: String,
}

/// The in-memory store of data, containing the Resources, Properties and Classes

#[derive(Clone)]
pub struct Store {
    hashmap: HashMap<String, Resource>,
}

impl Store {
    pub fn init() -> Store {
        return Store {
            hashmap: HashMap::new(),
        };
    }

    pub fn add_atom(&mut self, atoms: Vec<&Atom>) -> Result<()> {
        for atom in atoms {
            match self.hashmap.get_mut(&atom.subject) {
                Some(resource) => {
                    resource
                        .insert(atom.property.clone(), atom.value.clone())
                        .ok_or(&*format!("Failed to add atom"))?;
                }
                None => {
                    let mut resource: Resource = HashMap::new();
                    resource.insert(atom.property.clone(), atom.value.clone());
                    self.hashmap.insert(atom.subject.clone(), resource);
                }
            }
        }
        return Ok(());
    }

    // Replaces existing resource with the contents
    pub fn add_resource(&mut self, subject: String, resource: Resource) -> Result<()> {
        self.hashmap.insert(subject, resource)
            .ok_or("Could not add resource")?;
        return Ok(());
    }

    pub fn parse_ad3<'a, 'b>(&mut self, string: &'b String) -> Result<()> {
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
                    match &mut self.hashmap.get_mut(&*subject) {
                        Some(existing) => {
                            existing.insert(property.into(), value.into());
                        }
                        None => {
                            let mut resource: Resource = HashMap::new();
                            resource.insert(property.into(), value.into());
                            self.hashmap.insert(subject.into(), resource);
                        }
                    }
                }
                Some(char) => {
                    return Err(
                        format!("Parsing error at {:?}, cannot start with {}", line, char).into(),
                    )
                }
                None => {}
            };
        }
        return Ok(());
    }

    /// Reads an .ad3 (Atomic Data Triples) graph and adds it to the store
    pub fn read_store_from_file<'a>(&mut self, path: &'a PathBuf) -> Result<()> {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                self.parse_ad3(&contents)?;
                Ok(())
            },
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

    /// The depth is useful, since atomic data allows for cyclical (infinite-depth) relationships
    pub fn resource_to_json(&self, resource_url: &String, _depth: u32) -> Result<String> {
        use serde_json::{Map, Value};

        let resource = self.get(resource_url).ok_or("Resource not found")?;

        // Initiate JSON object
        let mut map = Map::new();

        // For every atom, find the key, datatype and add it to the @context
        for (prop_url, value) in resource.iter() {
            // Add it to the JSON object
            // Very naive implementation, should actually turn:
            // [ ] ResourceArrays into arrrays
            // [ ] URLS into @id things
            // [ ] Numbers into native numbers
            // [ ] Resoures into objects, if the nesting depth allows it
            let property = self.get_property(prop_url).unwrap();
            map.insert(property.shortname, Value::String(value.into()));
        }

        let obj = Value::Object(map);
        let string = serde_json::to_string_pretty(&obj).unwrap();

        return Ok(string);
    }

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
    /// Todo: return something more useful, give more context.
    pub fn get_path(&self, atomic_path: &str, mapping: &Mapping) -> Result<PathReturn> {
        // The first item of the path represents the starting Resource, the following ones are traversing the graph / selecting properties.
        let path_items: Vec<&str> = atomic_path.split(' ').collect();
        // For the first item, check the user mapping
        let id_url: String = mapping::try_mapping_or_url(&String::from(path_items[0]), mapping)
            .ok_or(&*format!("No url found for {}", path_items[0]))?;
        if path_items.len() == 1 {
            return Ok(PathReturn::Subject(id_url));
        }
        // The URL of the next resource
        let mut subject = id_url;
        // Set the currently selectred resource parent, which starts as the root of the search
        let mut resource: Option<&Resource> = self.hashmap.get(&subject);
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
                            .get(&atom.property)
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
            current = PathReturn::Atom(Atom {
                subject: subject.clone(),
                property: property_url.clone().unwrap(),
                value: value.clone().unwrap(),
                native_value: self
                    .get_native_value(&value.clone().unwrap(), &property_url.clone().unwrap())?,
            })
        }
        return Ok(current);
    }

    pub fn property_shortname_to_url(
        &self,
        shortname: &String,
        resource: &Resource,
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

    pub fn get(&self, resource_url: &String) -> Option<&Resource> {
        return self.get(resource_url);
    }

    // Returns an enum of the native value.
    // Validates the contents.
    pub fn get_native_value(&self, value: &String, property_url: &String) -> Result<Value> {
        let prop = self.get_property(property_url)?;
        match prop.data_type {
            DataType::Integer => {
                let val: i32 = value.parse()?;
                return Ok(Value::Integer(val));
            }
            DataType::String => return Ok(Value::String(value.clone())),
            DataType::MDString => return Ok(Value::MDString(value.clone())),
            DataType::Slug => {
                let re = Regex::new(SLUG_REGEX).unwrap();
                if re.is_match(&*value) {
                    return Ok(Value::Slug(value.clone()));
                }
                return Err(format!("Not a valid slug: {}", value).into());
            }
            DataType::AtomicUrl => {
                let re = Regex::new(DATE_REGEX).unwrap();
                if re.is_match(&*value) {
                    return Ok(Value::Date(value.clone()));
                }
                return Err(format!("Not a valid Atomic URL: {}", value).into());
            }
            DataType::ResourceArray => {
                let vector: Vec<String> = deserialize_json_array(value).unwrap();
                return Ok(Value::ResourceArray(vector));
            }
            DataType::Date => {
                let re = Regex::new(DATE_REGEX).unwrap();
                if re.is_match(&*value) {
                    return Ok(Value::Date(value.clone()));
                }
                return Err(format!("Not a valid date: {}", value).into());
            }
            DataType::Timestamp => {
                let val: i64 = value.parse()?;
                return Ok(Value::Timestamp(val));
            }
            DataType::Unsupported(unsup_url) => {
                return Ok(Value::UnkownValue(UnkownValue {
                    value: value.into(),
                    datatype: unsup_url.into(),
                }))
            }
        };
    }

    pub fn resource_to_ad3(
        &self,
        subject: &String,
        domain: Option<&String>,
    ) -> Result<String> {
        let mut string = String::new();
        let resource = self.get(subject).ok_or("Resource not found")?;
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
            let mut ad3_atom = serde_json::to_string(&vec![&mod_subject, property, value])
                .expect("Can't serialize");
            ad3_atom.push_str("\n");
            &string.push_str(&*ad3_atom);
        }
        return Ok(string);
    }

    pub fn validate_store(&self) -> Result<String> {
        todo!();
        for (url, properties) in self.hashmap.iter() {
            // Are all property URLs accessible?
            // Do the datatypes of the properties match the datatypes of the
            // if they are instances of a class, do they have the required fields?
            println!("{:?}: {:?}", url, properties);
        }
        return Err("Whoops".into());
    }
}

// A path can return one of many things
pub enum PathReturn {
    Subject(String),
    Atom(Atom),
}

pub const SLUG_REGEX: &str = r"^[a-z0-9]+(?:-[a-z0-9]+)*$";
pub const DATE_REGEX: &str = r"^\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01])$";

pub fn match_datatype(string: &String) -> DataType {
    match string.as_str() {
        urls::INTEGER => DataType::Integer,
        urls::STRING => DataType::String,
        urls::MDSTRING => DataType::MDString,
        urls::SLUG => DataType::Slug,
        urls::ATOMIC_URL => DataType::AtomicUrl,
        urls::RESOURCE_ARRAY => DataType::ResourceArray,
        urls::DATE => DataType::Date,
        urls::TIMESTAMP => DataType::Timestamp,
        unsupported_datatype => return DataType::Unsupported(unsupported_datatype.into()),
    }
}
