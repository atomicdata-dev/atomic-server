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
        // Requires compiling atomic-plugin-demo
        let module_u8 = include_bytes!(
            "../../../target/wasm32-unknown-unknown/release/atomic_plugin_example.wasm"
        );
        // let module_string = r#"
        // (module
        // (type $t0 (func (param i32) (result i32)))
        // (func $add_one (export "add_one") (type $t0) (param $p0 i32) (result i32)
        //     get_local $p0
        //     i32.const 1
        //     i32.add))
        // "#;

        let fn_name = "fibonacci";
        let arguments = &[Value::I32(10)];
        let wasm_store = wasmer::Store::default();
        // Creating this module can be costly, so it should probably be done earlier (server init)
        let module =
            Module::new(&wasm_store, module_u8).map_err(|e| format!("module error: {}", e))?;
        let result = run_wasm(&module, arguments, fn_name)?;
        let mut resource = Resource::new("sub".into());
        resource.set_propval_string(urls::DESCRIPTION.into(), &result, store)?;
        Ok(resource)
    }
}

/// Executes a single function from a WASM application.
/// Returns the first result as a String.
fn run_wasm(
    // Wasm string representation of executable code
    module: &Module,
    // Vector of arguments for the function
    arguments: &[wasmer::Val],
    // Name of the function
    fn_name: &str,
) -> AtomicResult<String> {
    // The module doesn't import anything, so we create an empty import object.
    let import_object = imports! {};
    let instance = Instance::new(module, &import_object)?;
    let result = instance.exports.get_function(fn_name)?.call(arguments)?;
    Ok(result[0].to_string())
}
