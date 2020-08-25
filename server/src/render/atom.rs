use atomic_lib::values::Value;
use atomic_lib::atoms::RichAtom;
use atomic_lib::store::Property;
use serde::Serialize;
use tera::escape_html;
use comrak::{markdown_to_html, ComrakOptions};

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
pub fn value_to_html(value: Value) -> String {
    match value {
        Value::Integer(i) => return format!("{}", i),
        Value::String(s) => return format!("{}", escape_html(&*s)),
        Value::Markdown(s) => return format!("{}", markdown_to_html(&*s, &ComrakOptions::default())),
        Value::Slug(s) => return format!("{}", escape_html(&*s)).into(),
        Value::AtomicUrl(s) => return format!("<a href=\"/get?path={}\">{}</a>", escape_html(&*s), escape_html(&*s)).into(),
        Value::ResourceArray(v) => {
            let mut string = String::from("");
            v.iter().for_each(|item| string.push_str(&*format!("<a href=\"/get?path={}\">{}</a>, ", escape_html(item), escape_html(item))));
            return string
        },
        Value::Date(s) => return format!("{:?}", s).into(),
        Value::Timestamp(i) => return format!("{}", i).into(),
        Value::Unsupported(unsup_url) => return format!("{:?}", unsup_url).into(),
    };
}

impl RenderAtom {
    pub fn from_rich_atom(atom: &RichAtom) -> RenderAtom {
        return RenderAtom {
            subject: atom.subject.clone(),
            property: atom.property.clone(),
            value: atom.value.clone(),
            native_value: atom.native_value.clone(),
            html: value_to_html(atom.native_value.clone()),
        }
    }
}
