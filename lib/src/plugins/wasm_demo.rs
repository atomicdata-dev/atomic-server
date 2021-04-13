use crate::{endpoints::Endpoint, errors::AtomicResult, urls, Resource, Storelike};
use wasmer::{Store, Module, Instance, Value, imports};

pub fn wasm_demo_endpoint() -> Endpoint {
    Endpoint {
        path: "/wasm".to_string(),
        params: [urls::SHORTNAME.to_string()].into(),
        description: "A WASM demo ".to_string(),
        shortname: "wasm".to_string(),
        handle: handle_wasm_demo_request,
    }
}

fn handle_wasm_demo_request(url: url::Url, store: &impl Storelike) -> AtomicResult<Resource> {
    let params = url.query_pairs();
    let mut var = None;
    for (k, v) in params {
        if let "shortname" = k.as_ref() {
            var = Some(v.to_string())
        };
    }
    if var.is_none() {
        wasm_demo_endpoint().to_resource(store)
    } else {
        let result = run_wasm()?;
        let mut resource = Resource::new("sub".into());
        resource.set_propval_string(urls::DESCRIPTION.into(), &result, store)?;
        Ok(resource)
    }
}


fn run_wasm() -> AtomicResult<String>{
    let module_wat = r#"
    (module
    (type $t0 (func (param i32) (result i32)))
    (func $add_one (export "add_one") (type $t0) (param $p0 i32) (result i32)
        get_local $p0
        i32.const 1
        i32.add))
    "#;

    let store = Store::default();
    let module = Module::new(&store, &module_wat)?;
    // The module doesn't import anything, so we create an empty import object.
    let import_object = imports! {};
    let instance = Instance::new(&module, &import_object)?;

    let add_one = instance.exports.get_function("add_one")?;
    let result = add_one.call(&[Value::I32(42)])?;
    assert_eq!(result[0], Value::I32(43));

    Ok(result[0].to_string())
}
