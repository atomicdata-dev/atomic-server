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

fn handle_path_request(url: url::Url, store: &impl Storelike) -> AtomicResult<Resource> {
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
    println!("path is some {:?}", path);
    let result = store.get_path(&path.unwrap(), None)?;
    match result {
        crate::storelike::PathReturn::Subject(subject) => {
          store.get_resource(&subject)
        }
        crate::storelike::PathReturn::Atom(_) => {
          // TODO: Create Atom resource, which contains a Subject, a Property and a Value.
          Err("Path resulted in a value - not a resource. ".into())
        }
    }
}
