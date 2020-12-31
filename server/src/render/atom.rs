use crate::errors::BetterResult;
use atomic_lib::atoms::RichAtom;
use atomic_lib::values::Value;
use atomic_lib::{storelike::Property, Atom, Storelike};
use comrak::{markdown_to_html, ComrakOptions};
use serde::Serialize;
use tera::escape_html;

/// Atom with all the props that make it suitable for rendering.
#[derive(Serialize)]
pub struct RenderAtom {
    subject: String,
    property: Property,
    value: String,
    native_value: Value,
    html: String,
}

/// Converts an Atomic Value to an HTML string suitable for display
/// Escapes HTML contents for safe value rendering
pub fn value_to_html(value: &Value) -> String {
    match value {
        Value::Integer(i) => format!("{}", i),
        Value::String(s) => escape_html(&*s),
        Value::Markdown(s) => markdown_to_html(&*s, &ComrakOptions::default()),
        Value::Slug(s) => escape_html(&*s),
        Value::AtomicUrl(s) => {
            let url = escape_html(&*s);
            // let name = store.get_resource(subject)
            // .unwrap_or(url).get(atomic_lib::urls::SHORTNAME)
            // .unwrap_or(url);
            format!(r#"<a href="{}">{}</a>"#, url, url)
        }
        Value::ResourceArray(v) => {
            let mut html = String::from("");
            v.iter().for_each(|item| {
                let url = escape_html(item);
                html.push_str(&*format!(r#"<a href="{}">{}</a>, "#, url, url))
            });
            html
        }
        Value::Date(s) => format!("{:?}", s),
        Value::Timestamp(i) => format!("{}", i),
        Value::Unsupported(unsup_url) => format!("{:?}", unsup_url),
        Value::NestedResource(n) => format!("{:?}", n),
        Value::Boolean(b) => format!("{}", b),
    }
}

impl RenderAtom {
    #[allow(dead_code)]
    pub fn from_rich_atom(atom: &RichAtom) -> RenderAtom {
        RenderAtom {
            subject: atom.subject.clone(),
            property: atom.property.clone(),
            value: atom.value.clone(),
            native_value: atom.native_value.clone(),
            html: value_to_html(&atom.native_value),
        }
    }

    pub fn from_atom(atom: Atom, store: &impl Storelike) -> BetterResult<RenderAtom> {
        let property = store.get_property(&atom.property)?;
        let native = Value::new(&atom.value, &property.data_type)?;

        Ok(RenderAtom {
            subject: atom.subject,
            property,
            value: atom.value,
            html: value_to_html(&native),
            native_value: native,
        })
    }
}
