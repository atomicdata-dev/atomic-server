use crate::types::*;

#[fp_bindgen_support::fp_export_signature]
pub async fn fetch_data(url: String) -> String;

#[fp_bindgen_support::fp_export_signature]
pub async fn my_async_exported_function() -> ComplexGuestToHost;

#[fp_bindgen_support::fp_export_signature]
pub fn my_complex_exported_function(a: ComplexHostToGuest) -> ComplexAlias;

#[fp_bindgen_support::fp_export_signature]
pub fn my_plain_exported_function(a: u32, b: u32) -> u32;
