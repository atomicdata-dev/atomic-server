use promptly::{prompt, prompt_opt};
use std::collections::HashMap;
use serde_json::de::from_str;

struct Model {
    required_fields: Vec<Property>,
    recommended_fields: Vec<Property>,
    /// Slug
    shortname: String,
    /// URL
    identifier: String,
}

struct Property {
    data_type: String,
    shortname: String,
    identifier: String,
}

enum DataType {
    Integer,
    String,
    File,
}

struct Instance {
    fields: Vec<Tuple>,
}

#[derive(Debug)]
struct Tuple {
    /// The URL of the Property
    property: String,
    /// The actual value, should not only be string but way more
    value: String,
}

/// Maps shortanmes to URLs
struct Mapping {
    shortname: String,
    url: String,
}

/// The in-memory store of data, containing the Resources, Properties and Classes
type Store = HashMap<String, Resource>;

/// The first string represents the URL of the Property, the second one its Value.
type Resource = HashMap<String, String>;

fn main() {
    // let mapping = read_mapping();
    let model = get_model("https://example.com/Person".into());

    let mut created_instance = Instance { fields: Vec::new() };

    let selected_model_url = model.identifier;

    // Sets the Class of the Resource
    let is_a = Tuple {
        property: "https://atomicdata.dev/properties/isA".into(),
        value: selected_model_url.into(),
    };

    created_instance.fields.push(is_a);

    for field in model.required_fields {
        let tuple = Tuple {
            value: prompt(field.shortname).unwrap(),
            property: field.identifier,
        };
        created_instance.fields.push(tuple);
    }

    for field in model.recommended_fields {
        let mut input: Option<String> = None;
        let msg = format!("{} (optional)", &field.shortname);
        match field.data_type.as_str() {
            STRING => {
                input = prompt_opt(&msg).unwrap();
            }
            INTEGER => {
                let number: Option<u32> = prompt_opt(&msg).unwrap();
                match number {
                    Some(nr) => {
                        input = Some(nr.to_string());
                    }
                    None => (),
                }
            }
            _ => {
                panic!("Unknown datatype")
            }
        };
        println!("input: {:?}", input);
        match input {
            Some(value) => {
                let tuple = Tuple {
                    value: value.clone(),
                    property: field.identifier,
                };
                created_instance.fields.push(tuple);
            }
            None => {}
        }
    }
    println!("Fields: {:?}", &created_instance.fields);
}

// Classes
const CLASS: &str = "https://atomicdata.dev/classes/Class";
const PROPERTY: &str = "https://atomicdata.dev/classes/Property";
const DATATYPE_CLASS: &str = "https://atomicdata.dev/classes/Datatype";

// Properties
const SHORTNAME: &str = "https://atomicdata.dev/properties/shortname";
const DESCRIPTION: &str = "https://atomicdata.dev/properties/description";
// ... for Properties
const IS_A: &str = "https://atomicdata.dev/properties/isA";
const DATATYPE_PROP: &str = "https://atomicdata.dev/properties/datatype";
// ... for Classes
const REQUIRES: &str = "https://atomicdata.dev/properties/requires";
const RECOMMENDS: &str = "https://atomicdata.dev/properties/recommends";

// Datatypes
const STRING: &str = "https://atomicdata.dev/datatypes/string";
const SLUG: &str = "https://atomicdata.dev/datatypes/slug";
const ATOMIC_URL: &str = "https://atomicdata.dev/datatypes/atomicURL";
const INTEGER: &str = "https://atomicdata.dev/datatypes/integer";
const RESOURCE_ARRAY: &str = "https://atomicdata.dev/datatypes/resourceArray";
const BOOLEAN: &str = "https://atomicdata.dev/datatypes/boolean";

fn get_model(subject: String) -> Model {
    let mut store: Store = HashMap::new();

    // Create the "Name" Property
    let mut name_prop_resource: Resource = HashMap::new();
    name_prop_resource.insert(IS_A.into(), PROPERTY.into());
    name_prop_resource.insert(SHORTNAME.into(), "name".into());
    name_prop_resource.insert(DESCRIPTION.into(), "The name of the person".into());
    name_prop_resource.insert(DATATYPE_PROP.into(), STRING.into());
    store.insert("https://example.com/name".into(), name_prop_resource);

    // Create the "Age" Property
    let mut age_prop_resource: Resource = HashMap::new();
    age_prop_resource.insert(IS_A.into(), PROPERTY.into());
    age_prop_resource.insert(SHORTNAME.into(), "age".into());
    age_prop_resource.insert(DESCRIPTION.into(), "The age of the person".into());
    age_prop_resource.insert(DATATYPE_PROP.into(), INTEGER.into());
    store.insert("https://example.com/age".into(), age_prop_resource);

    // Create the "Person" Class
    let mut person_class_resource: Resource = HashMap::new();
    person_class_resource.insert(IS_A.into(), CLASS.into());
    person_class_resource.insert(SHORTNAME.into(), "name".into());
    person_class_resource.insert(DESCRIPTION.into(), "A human bean".into());
    person_class_resource.insert(REQUIRES.into(), "[\"https://example.com/name\",\"https://example.com/age\"]".into());
    person_class_resource.insert(RECOMMENDS.into(), "[\"https://example.com/age\"]".into());
    store.insert("https://example.com/Person".into(), person_class_resource);

    println!("{:?}", store.keys());
    println!("{:?}", store.get("https://example.com/name"));

    // The string representation of the model
    let model_strings = store.get(&subject).expect("Model not found");
    let shortname = model_strings.get(SHORTNAME).expect("Model has no shortname");
    let requires_string = model_strings.get(REQUIRES).expect("No required props");
    let recommends_string = model_strings.get(RECOMMENDS).expect("No recommended props");
    let requires: Vec<Property> = get_properties(requires_string.into(), &store);
    let recommends: Vec<Property> = get_properties(recommends_string.into(), &store);

    fn get_properties(resource_array: String, store: &Store) -> Vec<Property> {
        let mut properties: Vec<Property> = vec![];
        let string_vec: Vec<String> = from_str(&*resource_array).unwrap();
        for prop_url in string_vec {
            let property_resource = store.get(&*prop_url).expect("Model not found");
            let property = Property {
                data_type: property_resource.get(DATATYPE_PROP).expect("Datatype not found").into(),
                shortname: property_resource.get(SHORTNAME).expect("Shortname not found").into(),
                identifier: prop_url.into(),
            };
            properties.push(property)
        }
        return properties;
    }

    let model = Model {
        required_fields: requires,
        recommended_fields: recommends,
        shortname: shortname.into(),
        identifier: subject,
    };

    // let name_prop = Property {
    //     data_type: STRING.into(),
    //     shortname: "name".into(),
    //     identifier: "https://example.com/name".into(),
    // };
    // let age_prop = Property {
    //     data_type: INTEGER.into(),
    //     shortname: "age".into(),
    //     identifier: "https://example.com/age".into(),
    // };
    // let model = Model {
    //     required_fields: vec![name_prop],
    //     recommended_fields: vec![age_prop],
    //     shortname: shortname.into(),
    //     identifier: "https://example.com/Person".into(),
    // };

    // println!("shortname: {:?}", model.shortname);

    // let name_prop = Property {
    //     data_type: DataType::String,
    //     shortname: "name".into(),
    //     identifier: "https://example.com/name".into(),
    // };
    // let age_prop = Property {
    //     data_type: DataType::Integer,
    //     shortname: "age".into(),
    //     identifier: "https://example.com/age".into(),
    // };
    // let model = Model {
    //     required_fields: vec![name_prop],
    //     recommended_fields: vec![age_prop],
    //     shortname: "person".into(),
    //     identifier: "https://example.com/Person".into(),
    // };
    return model;
}

fn read_mapping() -> Vec<Mapping> {
    let mapping: Vec<Mapping> = Vec::new();
    return mapping;
}
