use crate::errors::BetterResult;
use atomic_lib::atoms::RichAtom;
use atomic_lib::values::Value;
use atomic_lib::{schema::Property, Atom, Storelike};
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
pub fn value_to_html(value: &Value, store: &impl Storelike) -> String {
    match value {
        Value::Integer(i) => format!("{}", i),
        Value::String(s) => escape_html(&*s),
        Value::Markdown(s) => markdown_to_html(&*s, &ComrakOptions::default()),
        Value::Slug(s) => escape_html(&*s),
        Value::AtomicUrl(s) => {
            let url = escape_html(&*s);
            let display = try_shortname(s, store);
            format!(r#"<a href="{}">{}</a>"#, url, display)
        }
        Value::ResourceArray(v) => {
            let mut html = String::from("");
            v.iter().for_each(|item| {
                let url = escape_html(item);
                let display = try_shortname(item, store);
                html.push_str(&*format!(r#"<a href="{}">{}</a>, "#, url, display))
            });
            html
        }
        Value::Date(s) => format!("{:?}", s),
        Value::Timestamp(i) => {
            let datetime = chrono::NaiveDateTime::from_timestamp(i / 1000, 0);
            datetime.to_string()
        },
        Value::Unsupported(unsup_url) => format!("{:?}", unsup_url),
        Value::NestedResource(n) => format!("{:?}", n),
        Value::Boolean(b) => format!("{}", b),
    }
}

fn try_shortname(subject: &str, store: &impl Storelike) -> String {
    if let Ok(resource) = store.get_resource(subject) {
        if let Ok(shortname) = resource.get(atomic_lib::urls::SHORTNAME) {
            return shortname.to_string()
        }
    }
    subject.into()
}

impl RenderAtom {
    #[allow(dead_code)]
    pub fn from_rich_atom(atom: &RichAtom, store: &impl Storelike) -> RenderAtom {
        RenderAtom {
            subject: atom.subject.clone(),
            property: atom.property.clone(),
            value: atom.value.clone(),
            native_value: atom.native_value.clone(),
            html: value_to_html(&atom.native_value, store),
        }
    }

    pub fn from_atom(atom: Atom, store: &impl Storelike) -> BetterResult<RenderAtom> {
        let property = store.get_property(&atom.property)?;
        let native = Value::new(&atom.value, &property.data_type)?;

        Ok(RenderAtom {
            subject: atom.subject,
            property,
            value: atom.value,
            html: value_to_html(&native, store),
            native_value: native,
        })
    }
}
