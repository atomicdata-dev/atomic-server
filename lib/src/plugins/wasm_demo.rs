use crate::{endpoints::Endpoint, errors::AtomicResult, urls, Resource, Storelike};
use wasmer::{imports, Instance, Module, Value};

pub fn wasm_demo_endpoint() -> Endpoint {
    Endpoint {
        path: "/wasm".to_string(),
        // Ideally, these params are fully dynamic and constructed from the arguments for the WASM function
        params: [urls::SHORTNAME.to_string()].into(),
        description: "A WASM demo ".to_string(),
        shortname: "wasm".to_string(),
        handle: Some(handle_wasm_demo_request),
    }
}

fn handle_wasm_demo_request(
    url: url::Url,
    store: &impl Storelike,
    _for_agent: Option<&str>,
) -> AtomicResult<Resource> {
    let params = url.query_pairs();
    let mut var = None;
    for (k, v) in params {
        // This check for arguments specific to this function
        if let "shortname" = k.as_ref() {
            var = Some(v.to_string())
        };
    }
    if var.is_none() {
        wasm_demo_endpoint().to_resource(store)
    } else {
        // TODO: run the WASM code!
        Runtime::start()
    }
}
