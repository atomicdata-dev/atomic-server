//! Structs and models at the core of Atomic Schema (Class, Property, Datatype).

use crate::{Resource, Value, datatype::DataType, errors::AtomicResult, urls};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Property {
    // URL of the class
    pub class_type: Option<String>,
    // URL of the datatype
    pub data_type: DataType,
    pub shortname: String,
    pub subject: String,
    pub description: String,
}

impl PartialEq for Property {
    fn eq(&self, other: &Self) -> bool {
        self.subject == other.subject
    }
}

impl Property {
    /// Fetches a property by URL, returns a Property instance
    pub fn from_resource(resource: Resource) -> AtomicResult<Property> {
        let data_type = resource.get(urls::DATATYPE_PROP)?.to_string().parse()?;
        let shortname = resource.get(urls::SHORTNAME)?.to_string();
        let description = resource.get(urls::DESCRIPTION)?.to_string();
        let class_type = match resource.get(urls::CLASSTYPE_PROP) {
            Ok(classtype) => Some(classtype.to_string()),
            Err(_) => None,
        };

        Ok(Property {
            class_type,
            data_type,
            shortname,
            description,
            subject: resource.get_subject().into(),
        })
    }

    /// Convert to resource
    pub fn to_resource(&self) -> AtomicResult<Resource> {
        let mut resource = Resource::new(self.subject.clone());
        resource.set_propval_unsafe(urls::IS_A.into(), Value::ResourceArray(vec![urls::PROPERTY.into()]))?;
        resource.set_propval_unsafe(urls::SHORTNAME.into(), Value::Slug(self.shortname.clone()))?;
        resource.set_propval_unsafe(urls::DESCRIPTION.into(), Value::String(self.description.clone()))?;
        resource.set_propval_unsafe(urls::DATATYPE_PROP.into(), Value::AtomicUrl(self.data_type.to_string()))?;
        if let Some(classtype) = &self.class_type {
            resource.set_propval_unsafe(urls::CLASSTYPE_PROP.into(), Value::AtomicUrl(classtype.clone()))?;
        }

        Ok(resource)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Class {
    pub requires: Vec<String>,
    pub recommends: Vec<String>,
    pub shortname: String,
    pub description: String,
    /// URL
    pub subject: String,
}

impl Class {
    /// Creates a Class from a Resource
    pub fn from_resource(resource: &Resource) -> AtomicResult<Class> {
        let mut requires = Vec::new();
        if let Ok(reqs) = resource.get(urls::REQUIRES) {
            for prop_sub in reqs.to_vec()? {
                requires.push(prop_sub.clone())
            }
        }

        let mut recommends = Vec::new();
        if let Ok(recs) = resource.get(urls::RECOMMENDS) {
            for rec_subject in recs.to_vec()? {
                recommends.push(rec_subject.clone())
            }
        }

        let shortname = resource.get(urls::SHORTNAME)?.to_string();
        let description = resource.get(urls::DESCRIPTION)?.to_string();

        Ok(Class {
            requires,
            recommends,
            shortname,
            subject: resource.get_subject().into(),
            description,
        })
    }

    /// Converts Class to a Resource
    pub fn to_resource(&self) -> AtomicResult<Resource> {
        let mut resource = Resource::new(self.subject.clone());
        resource.set_propval_unsafe(urls::IS_A.into(), Value::ResourceArray(vec![urls::CLASS.into()]))?;
        resource.set_propval_unsafe(urls::SHORTNAME.into(), Value::Slug(self.shortname.clone()))?;
        resource.set_propval_unsafe(urls::DESCRIPTION.into(), Value::String(self.description.clone()))?;
        if !self.requires.is_empty() {
            resource.set_propval_unsafe(urls::REQUIRES.into(), Value::ResourceArray(self.requires.clone()))?;
        }
        if !self.requires.is_empty() {
            resource.set_propval_unsafe(urls::RECOMMENDS.into(), Value::ResourceArray(self.recommends.clone()))?;
        }
        Ok(resource)
    }
}
