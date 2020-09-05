use crate::{ResourceString, errors::AtomicResult, parse::parse_ad3};

/// Fetches a resource by Subject using HTTP.
/// Does not save to the store.
/// Only adds atoms with matching subjects match.
pub fn fetch_resource(subject: &String) -> AtomicResult<ResourceString> {
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
        return Err(format!("No valid atoms in {}", subject).into());
    }
    Ok(resource)
}
