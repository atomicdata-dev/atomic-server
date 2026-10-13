use super::*;

#[cfg(test)]
mod private_drive_tests {
    use super::*;
    use crate::Storelike;

    #[tokio::test]
    async fn setup_uses_the_derived_private_drive_did() {
        let store = Db::init_temp("private_drive_setup").await.unwrap();
        let (_agent, drive) = store.setup("Alice").await.unwrap();
        let expected = store.private_drive_subject().unwrap();
        assert_eq!(drive, expected);
        assert_eq!(store.ensure_private_drive().await.unwrap(), expected);
    }

    #[tokio::test]
    async fn extra_drive_is_listed_on_the_private_drive() {
        let store = Db::init_temp("private_drive_list").await.unwrap();
        let (_agent, personal) = store.setup("Alice").await.unwrap();
        let extra = store.create_drive("Project").await.unwrap();
        assert_ne!(extra, personal);

        let listed = store
            .get_resource(&personal.as_str().into())
            .await
            .unwrap()
            .get(urls::DRIVES)
            .unwrap()
            .to_subjects(None)
            .unwrap();
        assert!(
            listed.iter().any(|s| s == &extra),
            "private drive should list {extra}, got {listed:?}"
        );
        store.set_active_drive(&personal).unwrap();
        let drives = store.list_drives().await.unwrap();
        assert_eq!(drives.len(), 2);
        assert!(drives.iter().any(|d| d.subject == personal));
        assert!(drives
            .iter()
            .any(|d| d.subject == extra && d.name == "Project"));
    }
}
