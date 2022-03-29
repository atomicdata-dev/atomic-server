use crate::types::*;

#[fp_bindgen_support::fp_import_signature]
pub fn count_words(string: String) -> Result<u16, String>;

#[fp_bindgen_support::fp_import_signature]
/// Logs a message to the (development) console.
pub fn log(message: String);

#[fp_bindgen_support::fp_import_signature]
pub async fn make_request(opts: RequestOptions) -> Result<Response, RequestError>;

#[fp_bindgen_support::fp_import_signature]
pub async fn my_async_imported_function() -> ComplexHostToGuest;

#[fp_bindgen_support::fp_import_signature]
/// This one passes complex data types. Things are getting interesting.
pub fn my_complex_imported_function(a: ComplexAlias) -> ComplexHostToGuest;

#[fp_bindgen_support::fp_import_signature]
/// This is a very simple function that only uses primitives. Our bindgen should have little
/// trouble with this.
pub fn my_plain_imported_function(a: u32, b: u32) -> u32;
