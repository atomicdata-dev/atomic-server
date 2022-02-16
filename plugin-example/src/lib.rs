#[no_mangle]
pub fn fibonacci(n: u32) -> u32 {
    // let resp = reqwasm::Request::get("/path").send().await.unwrap();
    // assert_eq!(resp.status(), 200);

    match n {
        0 | 1 => n,
        _ => fibonacci(n - 1) + fibonacci(n - 2),
    }
}

// #[no_mangle]
// pub async fn fetch() -> String {
//     let resp = reqwasm::http::Request::get("/path").send().await.unwrap();
//     assert_eq!(resp.status(), 200);
//     resp.text().await.unwrap()
// }

#[no_mangle]
pub fn author() -> String {
    String::from("Hello from Rust")
}
