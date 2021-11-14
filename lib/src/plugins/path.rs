use crate::{endpoints::Endpoint, errors::AtomicResult, urls, Resource, Storelike};

pub fn path_endpoint() -> Endpoint {
    Endpoint {
        path: "/path".to_string(),
        params: [urls::PATH.to_string()].into(),
        description: "An Atomic Path is a string that starts with the URL of some Atomic Resource, followed by one or multiple other Property URLs or Property Shortnames. It resolves to one specific Resource or Value. At this moment, Values are not yet supported.".to_string(),
        shortname: "path".to_string(),
        handle: handle_path_request,
    }
}

fn handle_path_request(
    url: url::Url,
    store: &impl Storelike,
    for_agent: Option<String>,
) -> AtomicResult<Resource> {
    let params = url.query_pairs();
    let mut path = None;
    for (k, v) in params {
        if let "path" = k.as_ref() {
            path = Some(v.to_string())
        };
    }
    if path.is_none() {
        return path_endpoint().to_resource(store);
    }
    let result = store.get_path(&path.unwrap(), None, for_agent)?;
    match result {
        crate::storelike::PathReturn::Subject(subject) => store.get_resource(&subject),
        crate::storelike::PathReturn::Atom(atom) => {
            let mut resource = Resource::new(url.to_string());
            resource.set_propval_string(urls::ATOM_SUBJECT.into(), &atom.subject, store)?;
            resource.set_propval_string(urls::ATOM_PROPERTY.into(), &atom.property, store)?;
            resource.set_propval_string(urls::ATOM_VALUE.into(), &atom.value.to_string(), store)?;
            Ok(resource)
        }
    }
}
