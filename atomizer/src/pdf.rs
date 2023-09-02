use atomic_lib::resources::PropVals;

const CONTENT_PROP: &str = atomic_lib::urls::DESCRIPTION;

/// Extracts the text from a PDF file.
pub fn atomize(mut file: crate::file::File) -> PropVals {
    let mut props = PropVals::new();
    let bytes = file.bytes();
    let text = pdf_extract::extract_text_from_mem(&bytes).unwrap();
    props.insert(CONTENT_PROP.into(), atomic_lib::Value::Markdown(text));
    props
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::File;

    #[test]
    fn load_pdf() {
        let f = File::open("./test/docs-demo.pdf").unwrap();
        let propvals = f.to_propvals();
        let content = propvals.get(CONTENT_PROP).unwrap();
        assert!(content.to_string().contains("Atomic Data"));
    }
}
