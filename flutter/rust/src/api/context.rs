//! Plain text of a resource, to give an AI as context
//! (`atomic_lib::host::context`).

#[cfg(test)]
mod tests;

use super::simple::state::{db, err};

/// Readable text for the resource `subject` from the local store: title, class,
/// description, simple properties, the titles of the children of a folder or
/// drive, and the text of a document. At most `max_chars` characters.
pub async fn read_resource_text(subject: String, max_chars: u32) -> Result<String, String> {
    atomic_lib::host::context::read_resource_text(db()?, &subject, max_chars as usize)
        .await
        .map_err(err)
}
