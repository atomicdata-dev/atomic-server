//! Validate the Store and create a ValidationReport.
//! Might be deprecated soon, as Validation hasn't been necessary since parsing has built-in data validation.

/// Checks Atomic Data in the store for validity.
/// Returns an Error if it is not valid.
///
/// Validates:
///
/// - [X] If the Values can be parsed using their Datatype (e.g. if Integers are integers)
/// - [X] If all required fields of the class are present
/// - [X] If the URLs are publicly accessible
/// - [ ] ..and return the right type of data?
/// - [X] Returns a report, instead of throwing an error
#[allow(dead_code, unreachable_code)]
pub fn validate_store(
    store: &impl crate::Storelike,
    fetch_items: bool,
) -> crate::validate::ValidationReport {
    type Error = String;
    let mut resource_count: u8 = 0;
    let mut atom_count: u8 = 0;
    let mut unfetchable: Vec<(String, Error)> = Vec::new();
    let mut invalid_value: Vec<(crate::Atom, Error)> = Vec::new();
    let mut unfetchable_props: Vec<(String, Error)> = Vec::new();
    let mut unfetchable_classes: Vec<(String, Error)> = Vec::new();
    // subject, property, class
    let mut missing_props: Vec<(String, String, String)> = Vec::new();
    for resource in store.all_resources(true) {
        let subject = resource.get_subject();
        let propvals = resource.get_propvals();
        println!("Subject: {:?}", subject);
        println!("Resource: {:?}", propvals);
        resource_count += 1;

        if fetch_items {
            match crate::client::fetch_resource(subject, store, store.get_default_agent().ok()) {
                Ok(_) => {}
                Err(e) => unfetchable.push((subject.clone(), e.to_string())),
            }
        }

        let mut found_props: Vec<String> = Vec::new();

        for (prop_url, value) in propvals {
            atom_count += 1;

            let property = match store.get_property(prop_url) {
                Ok(prop) => prop,
                Err(e) => {
                    unfetchable_props.push((prop_url.clone(), e.to_string()));
                    break;
                }
            };

            // Maybe this is no longer needed, because no store uses strings anymore
            match crate::Value::new(&value.to_string(), &property.data_type) {
                Ok(_) => {}
                Err(e) => invalid_value.push((
                    crate::Atom::new(subject.clone(), prop_url.clone(), value.clone()),
                    e.to_string(),
                )),
            };
            found_props.push(prop_url.clone());
        }
        let classes = match store.get_classes_for_subject(subject) {
            Ok(classes) => classes,
            Err(e) => {
                unfetchable_classes.push((subject.clone(), e.to_string()));
                break;
            }
        };
        for class in classes {
            println!("Class: {:?}", class.shortname);
            println!("Found: {:?}", found_props);
            for required_prop_subject in class.requires {
                match store.get_property(&required_prop_subject) {
                    Ok(required_prop) => {
                        println!("Required: {:?}", required_prop.shortname);
                        if !found_props.contains(&required_prop.subject) {
                            missing_props.push((
                                subject.clone(),
                                required_prop.subject.clone(),
                                class.subject.clone(),
                            ));
                        }
                    }
                    Err(e) => unfetchable.push((required_prop_subject, e.to_string())),
                }
            }
        }
        println!("{:?} Valid", subject);
    }
    crate::validate::ValidationReport {
        unfetchable,
        unfetchable_classes,
        unfetchable_props,
        invalid_value,
        resource_count,
        atom_count,
    }
}

pub struct ValidationReport {
    pub resource_count: u8,
    pub atom_count: u8,
    pub unfetchable: Vec<(String, String)>,
    pub invalid_value: Vec<(crate::Atom, String)>,
    pub unfetchable_props: Vec<(String, String)>,
    pub unfetchable_classes: Vec<(String, String)>,
}

impl ValidationReport {
    pub fn is_valid(&self) -> bool {
        self.unfetchable.is_empty()
            && self.unfetchable_classes.is_empty()
            && self.unfetchable_props.is_empty()
            && self.invalid_value.is_empty()
    }
}

impl std::fmt::Display for ValidationReport {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.is_valid() {
            fmt.write_str("Valid!")?;
            return Ok(());
        }
        for (subject, error) in &self.unfetchable {
            fmt.write_str(&*format!("Cannot fetch Resource {}: {} \n", subject, error))?;
        }
        for (subject, error) in &self.unfetchable_classes {
            fmt.write_str(&*format!("Cannot fetch Class {}: {} \n", subject, error))?;
        }
        for (subject, error) in &self.unfetchable_props {
            fmt.write_str(&*format!("Cannot fetch Property {}: {} \n", subject, error))?;
        }
        for (atom, error) in &self.invalid_value {
            fmt.write_str(&*format!("Invalid value {:?}: {} \n", atom, error))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{Store, Storelike};

    #[test]
    fn validate_populated() {
        let store = Store::init().unwrap();
        store.populate().unwrap();
        // let report = store.validate();
        // assert!(report.atom_count > 30);
        // assert!(report.resource_count > 5);
        // assert!(report.is_valid());
    }
}
