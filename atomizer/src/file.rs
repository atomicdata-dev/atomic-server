use std::{collections::HashMap, error::Error};

use atomic_lib::resources::PropVals;
use mime_guess::Mime;

use crate::pdf;

pub struct File {
    filename: String,
    mime: Mime,
    bytes: Vec<u8>,
}

impl File {
    pub fn open(filename: &str) -> Result<File, Box<dyn Error>> {
        let bytes = std::fs::read(filename)?;
        let mime = mime_guess::from_path(filename).first_or_octet_stream();

        Ok(File {
            filename: filename.to_string(),
            mime,
            bytes,
        })
    }

    /// Creates property-value combinations based on the file's contents.
    /// Defaults to an empty HashMap if the file type is not supported.
    pub fn atomize(&self) -> PropVals {
        match self.mime.to_string().as_str() {
            "application/pdf" => pdf::atomize(self),
            _ => HashMap::new(),
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
