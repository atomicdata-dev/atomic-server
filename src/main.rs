use promptly::{prompt, prompt_opt};

struct Model {
    required_fields: Vec<Property>,
    recommended_fields: Vec<Property>,
    /// Slug
    shortname: String,
    /// URL
    identifier: String,
}

struct Property {
    data_type: DataType,
    shortname: String,
    identifier: String,
}

enum DataType {
    u32,
    String,
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

fn main() {
    let name_prop = Property {
        data_type: DataType::String,
        shortname: "name".into(),
        identifier: "https://example.com/name".into(),
    };
    let age_prop = Property {
        data_type: DataType::u32,
        shortname: "age".into(),
        identifier: "https://example.com/age".into(),
    };
    let person = Model {
        required_fields: vec![name_prop],
        recommended_fields: vec![age_prop],
        shortname: "person".into(),
        identifier: "https://example.com/Person".into(),
    };

    let mut created_instance = Instance { fields: Vec::new() };

    let selected_model_url = person.identifier;

    let model = Tuple {
        property: "https://atomicdata.dev/properties/isA".into(),
        value: selected_model_url.into(),
    };

    created_instance.fields.push(model);

    for field in person.required_fields {
        let tuple = Tuple {
            value: prompt(field.shortname).unwrap(),
            property: field.identifier,
        };
        created_instance.fields.push(tuple);
    }

    for field in person.recommended_fields {
        let msg = format!("{} (optional)", field.shortname);
        match prompt_opt(msg).unwrap() {
            Some(value) => {
                let tuple = Tuple {
                    value: value,
                    property: field.identifier,
                };
                created_instance.fields.push(tuple);
            }
            None => {}
        }
    }

    println!("Fields: {:?}", created_instance.fields);
}

/// Serialized to NDJSON Tuples
fn serialize_to_ad2(tuples: Vec<Tuple>) {

}
