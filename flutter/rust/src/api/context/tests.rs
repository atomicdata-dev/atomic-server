//! `read_resource_text` against the real store the other bridge tests share.

use super::*;
use crate::api::simple::tests::shared_drive;

/// A drive of its own: writes under the shared drive race with the tests that
/// rewrite its lists (favorites, conversations).
async fn own_drive(name: &str) -> String {
    shared_drive().await;
    let _one_at_a_time = crate::api::simple::tests::PRIVATE_DRIVE.lock().await;
    db().unwrap().create_drive(name).await.unwrap()
}

async fn folder(parent: &str, name: &str) -> String {
    db().unwrap()
        .create_resource(urls::FOLDER, parent, name, None)
        .await
        .unwrap()
}

#[tokio::test]
async fn folder_text_lists_title_class_and_children() {
    let drive = &own_drive("Ctx drive").await;
    let parent = folder(drive, "Ctx parent").await;
    folder(&parent, "Ctx child one").await;
    folder(&parent, "Ctx child two").await;

    let text = read_resource_text(parent, 4000).await.unwrap();
    assert!(text.starts_with("Ctx parent\n"), "{text}");
    assert!(text.to_lowercase().contains("class: folder"), "{text}");
    assert!(text.contains("- Ctx child one"), "{text}");
    assert!(text.contains("- Ctx child two"), "{text}");
}

#[tokio::test]
async fn resource_text_has_its_description() {
    let drive = &own_drive("Ctx drive").await;
    let subject = folder(drive, "Ctx described").await;
    let store = db().unwrap();
    let mut resource = store
        .get_resource(&Subject::from(subject.as_str()))
        .await
        .unwrap();
    resource
        .set_string(
            urls::DESCRIPTION.into(),
            "A quokka lives here",
            store.as_ref(),
        )
        .await
        .unwrap();
    resource.save(store.as_ref()).await.unwrap();

    let text = read_resource_text(subject, 4000).await.unwrap();
    assert!(text.contains("Description: A quokka lives here"), "{text}");
}

#[tokio::test]
async fn text_is_capped() {
    let drive = &own_drive("Ctx drive").await;
    let subject = folder(drive, "Ctx a long enough title").await;
    let text = read_resource_text(subject, 10).await.unwrap();
    assert_eq!(text.chars().count(), 10);
}
