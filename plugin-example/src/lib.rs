use atomic_bindings::*;
use std::collections::{BTreeMap, HashMap};
use std::panic;

fn init_panic_hook() {
    use std::sync::Once;
    static SET_HOOK: Once = Once::new();
    SET_HOOK.call_once(|| {
        panic::set_hook(Box::new(|info| log(info.to_string())));
    });
}

#[fp_export_impl(atomic_bindings)]
fn my_plain_exported_function(a: u32, b: u32) -> u32 {
    init_panic_hook();

    a + my_plain_imported_function(a, b)
}

#[fp_export_impl(atomic_bindings)]
fn my_complex_exported_function(a: ComplexHostToGuest) -> ComplexGuestToHost {
    init_panic_hook();

    let simple = Simple {
        bar: a.simple.bar,
        foo: 2 * a.simple.foo,
    };

    my_complex_imported_function(ComplexGuestToHost {
        map: BTreeMap::new(),
        simple: simple.clone(),
    });

    ComplexGuestToHost {
        map: BTreeMap::new(),
        simple,
    }
}

#[fp_export_impl(atomic_bindings)]
async fn my_async_exported_function() -> ComplexGuestToHost {
    init_panic_hook();

    let result = my_async_imported_function().await;
    ComplexGuestToHost {
        map: BTreeMap::new(),
        simple: result.simple,
    }
}

#[fp_export_impl(atomic_bindings)]
async fn fetch_data(url: String) -> String {
    init_panic_hook();

    let result = make_request(RequestOptions {
        url,
        method: RequestMethod::Get,
        headers: HashMap::new(),
        body: None,
    })
    .await;

    match result {
        Ok(response) => {
            String::from_utf8(response.body.to_vec()).unwrap_or_else(|_| "Invalid utf8".to_owned())
        }
        Err(err) => format!("Error: {:?}", err),
    }
}
