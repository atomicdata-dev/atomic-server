use atomic_bindings::*;

fn log(msg: String) {
    println!("Provider log: {}", msg);
}

fn my_complex_imported_function(a: ComplexAlias) -> ComplexHostToGuest {
    make_host_to_guest()
}

fn my_plain_imported_function(a: u32, b: u32) -> u32 {
    a + b
}

fn count_words(string: String) -> Result<u16, String> {
    Ok(1337)
}

async fn my_async_imported_function() -> ComplexHostToGuest {
    make_host_to_guest()
}

fn make_host_to_guest() -> ComplexHostToGuest {
    ComplexHostToGuest {
        simple: Simple {
            bar: "asd".to_owned(),
            foo: 0,
        },
        list: vec![],
        points: vec![],
        recursive: vec![],
        complex_nested: None,
        r#type: "Foobar".to_owned(),
        value: Value::Integer(1),
    }
}

async fn make_request(opts: RequestOptions) -> Result<Response, RequestError> {
    Err(RequestError::Other {
        reason: "Not yet implemented".to_owned(),
    })
}
