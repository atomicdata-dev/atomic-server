use crate::{endpoints::Endpoint, errors::AtomicResult, urls, Resource, Storelike};

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
        // Runtime::start()
        #[cfg_attr(feature = "plugins", allow(unused_variables))]
        {
            let module_u8 = include_bytes!(
                // "../../../target/wasm32-unknown-unknown/release/plugin_example.wasm"
                "../../../plugin-example/plugin_example.wasm"
            );
            let runtime =
                crate::plugins::generated_runtime::bindings::Runtime::new(&module_u8).unwrap();
            let result = runtime.my_plain_exported_function(1, 2).unwrap();
        }
        let resource = Resource::new("adwda".into());
        println!("We have a var!");
        Ok(resource)
    }
}
