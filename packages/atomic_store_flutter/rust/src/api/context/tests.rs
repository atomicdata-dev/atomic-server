//! `read_resource_text` through the bridge, against the real store the other
//! bridge tests share. The text itself is tested in `atomic_lib::host::context`.

use super::*;
use crate::api::simple::tests::shared_drive;
use atomic_lib::urls;

/// A drive of its own: writes under the shared drive race with the tests that
/// rewrite its lists (favorites, conversations).
async fn own_drive(name: &str) -> String {
    shared_drive().await;
    let _one_at_a_time = crate::api::simple::tests::PRIVATE_DRIVE.lock().await;
    db().unwrap().create_drive(name).await.unwrap()
}

#[tokio::test]
async fn folder_text_lists_title_class_and_children() {
    let drive = &own_drive("Ctx drive").await;
    let store = db().unwrap();
    let parent = store
        .create_resource(urls::FOLDER, drive, "Ctx parent", None)
        .await
        .unwrap();
    store
        .create_resource(urls::FOLDER, &parent, "Ctx child one", None)
        .await
        .unwrap();

    let text = read_resource_text(parent, 4000).await.unwrap();
    assert!(text.starts_with("Ctx parent\n"), "{text}");
    assert!(text.to_lowercase().contains("class: folder"), "{text}");
    assert!(text.contains("- Ctx child one"), "{text}");
}
