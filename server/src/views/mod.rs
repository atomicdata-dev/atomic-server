//! Views contain logic for rendering specific templates.
//! These might become extendable one day.
//!
//! Adding a custom view is done by:
//! - creating a template `view.html` in `/templates`
//! - creating a module with a `render_thing` function. Make sure all structs derive `Serialize`, and use only the datatypes available in Tera.
//! - registering it for a class in `resource::render_resource`

pub mod class;
pub mod collection;
pub mod resource;
