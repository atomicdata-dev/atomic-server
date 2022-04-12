/*!
# Migrations

Whenever the schema of the database changes, a newer version will not be able to read an older database.
Therefore, we need migrations to convert the old schema to the new one.
 */

use crate::{errors::AtomicResult, Db};

// Checks the current version(s) of the internal Store, and performs migrations if needed.
fn migrate_maybe(store: &mut Db) -> AtomicResult<()> {
    let internal = store.db.open_tree("internal")?;

    let version: i16 = if let Some(v) = internal.get(b"version_resources")? {
        v.try_into()?
    } else {
        0
    };

    Ok(())
}

// Change the subjects from `bincode` to `.as_bytes()`
fn v0_to_v1(store: &mut Db) -> AtomicResult<()> {
    let new = store.db.open_tree("resources_new_temp")?;
    for item in store.resources.into_iter() {
        let (subject, resource_bin) = item.expect("Unable to perform migration");
        let subject: String =
            bincode::deserialize(&subject).expect("Unable to deserialize subject");
        new.insert(subject.as_bytes(), resource_bin)?;
    }
    Ok(())
}
