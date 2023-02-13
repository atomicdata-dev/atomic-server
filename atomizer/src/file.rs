use std::{collections::HashMap, error::Error, io::Read};

use atomic_lib::resources::PropVals;
use mime_guess::Mime;

pub struct File {
    filename: String,
    mime: Mime,
    reader: std::io::BufReader<std::fs::File>,
}

impl File {
    pub fn open(filename: &str) -> Result<File, Box<dyn Error>> {
        let bytes = std::fs::File::open(filename)?;
        let reader = std::io::BufReader::new(bytes);
        let mime = mime_guess::from_path(filename).first_or_octet_stream();

        Ok(File {
            filename: filename.to_string(),
            mime,
            reader,
        })
    }

    /// Creates property-value combinations based on the file's contents.
    /// Defaults to an empty HashMap if the file type is not supported.
    pub fn atomize(self) -> PropVals {
        match self.mime.to_string().as_str() {
            "application/pdf" => crate::pdf::atomize(self),
            "image/jpeg" => crate::image::atomize(self),
            _ => HashMap::new(),
        }
    }

    pub fn bytes(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut buffer = vec![];
        self.reader.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    pub fn reader(&mut self) -> &mut std::io::BufReader<std::fs::File> {
        &mut self.reader
    }

    pub fn mime(&self) -> &Mime {
        &self.mime
    }

    pub fn filename(&self) -> &str {
        &self.filename
    }
}
