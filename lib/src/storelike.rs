use std::collections::HashMap;
use crate::values::{match_datatype, DataType};
use crate::urls;
use serde::Serialize;
use crate::errors::Result;

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
/// Storelike serves as a basic store Trait, agnostic of how it functions under the hood.
/// This is useful, because we can create methods for Storelike that will work with either in-memory
/// stores, as well as with persistend on-disk stores.
pub trait Storelike {
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

    /// Fetches a property by URL, returns a Property instance
    fn get_property(&self, url: &String) -> Result<Property> {
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

}
