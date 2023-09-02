use std::{collections::HashMap, error::Error, io::Read};

use atomic_lib::resources::PropVals;
use mime_guess::Mime;

pub struct File {
    filename: String,
    mime: Mime,
    bytes: Vec<u8>,
}

impl File {
    pub fn open(filename: &str) -> Result<File, Box<dyn Error>> {
        let file = std::fs::File::open(filename)?;
        let bytes = std::io::BufReader::new(file)
            .bytes()
            .collect::<Result<Vec<u8>, _>>()?;
        let mime = mime_guess::from_path(filename).first_or_octet_stream();

        Ok(File {
            filename: filename.to_string(),
            mime,
            bytes,
        })
    }

    pub fn from_filename_bytes(filename: &str, bytes: Vec<u8>) -> Result<File, Box<dyn Error>> {
        let mime = mime_guess::from_path(filename).first_or_octet_stream();

        Ok(File {
            filename: filename.to_string(),
            mime,
            bytes,
        })
    }

    /// Creates property-value combinations based on the file's contents.
    /// Defaults to an empty HashMap if the file type is not supported.
    pub fn to_propvals(self) -> PropVals {
        match self.mime.to_string().as_str() {
            "application/pdf" => crate::pdf::atomize(self),
            "image/jpeg" => crate::image::atomize(self),
            _ => HashMap::new(),
        }
    }

    pub fn bytes(&mut self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub fn mime(&self) -> &Mime {
        &self.mime
    }

    pub fn filename(&self) -> &str {
        &self.filename
    }
}
