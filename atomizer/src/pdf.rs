use atomic_lib::resources::PropVals;

const content_prop: &str = "content";

/// Extracts the text from a PDF file.
pub fn atomize(file: &crate::file::File) -> PropVals {
    let mut props = PropVals::new();
    let mut s = String::new();
    let mut output = pdf_extract::PlainTextOutput::new(&mut s);
    let text = pdf_extract::extract_text_mem(file.bytes()).unwrap();
    props.insert(content_prop.into(), atomic_lib::Value::String(text));
    props
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::File;

    #[test]
    fn load_pdf() {
        let f = File::open("./test/docs-demo.pdf").unwrap();
        let propvals = f.atomize();
        let content = propvals.get(content_prop).unwrap();
        assert!(content.to_string().contains("Atomic Data"));
    }
}
