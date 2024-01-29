use crate::{
    endpoints::{Endpoint, HandleGetContext},
    errors::AtomicResult,
    urls, Resource, Storelike,
};

pub fn path_endpoint() -> Endpoint {
    Endpoint {
        path: "/path".to_string(),
        params: [urls::PATH.to_string()].into(),
        description: "An Atomic Path is a string that starts with the URL of some Atomic Resource, followed by one or multiple other Property URLs or Property Shortnames. It resolves to one specific Resource or Value. At this moment, Values are not yet supported.".to_string(),
        shortname: "path".to_string(),
        handle: Some(handle_path_request),
        handle_post: None,
    }
}

#[tracing::instrument]
fn handle_path_request(context: HandleGetContext) -> AtomicResult<Resource> {
    let HandleGetContext {
        store,
        for_agent,
        subject,
    } = context;
    let params = subject.query_pairs();
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
        crate::storelike::PathReturn::Subject(subject) => {
            store.get_resource_extended(&subject, false, for_agent)
        }
        crate::storelike::PathReturn::Atom(atom) => {
            let mut resource = Resource::new(subject.to_string());
            resource.set_string(urls::ATOM_SUBJECT.into(), &atom.subject, store)?;
            resource.set_string(urls::ATOM_PROPERTY.into(), &atom.property, store)?;
            resource.set_string(urls::ATOM_VALUE.into(), &atom.value.to_string(), store)?;
            Ok(resource)
        }
    }
}
