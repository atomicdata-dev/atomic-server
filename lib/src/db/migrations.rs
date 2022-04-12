/*!
# Migrations

Whenever the schema of the database changes, a newer version will not be able to read an older database.
Therefore, we need migrations to convert the old schema to the new one.
 */

use crate::{errors::AtomicResult, Db};

// Change the subjects from `bincode` to `.as_bytes()`
fn v0_to_v1(store: &mut Db) -> AtomicResult<()> {
    let new = store.db.open_tree("resources_new")?;
    for item in store.resources.into_iter() {
        let (subject, resource_bin) = item.expect("Unable to perform migration");
        let subject: String =
            bincode::deserialize(&subject).expect("Unable to deserialize subject");
        new.insert(subject.as_bytes(), resource_bin)?;
    }
    Ok(())
}
