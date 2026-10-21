//! New resources made on the device, as the web app's "New" buttons make
//! them: a class, a name and the drive as parent, signed by this device's
//! agent and queued in the outbox like every other local write.

use super::{own_commit_opts, LocalWritePusher};
use crate::{
    commit::CommitBuilder, errors::AtomicResult, runtime::AtomicNode, urls, Commit, Storelike,
    Value,
};

/// The name a resource gets when none was given.
pub const UNTITLED: &str = "Untitled";

/// Create a resource of `class_url` named `name` (trimmed; [`UNTITLED`] when
/// empty) directly under `drive`, signed by the device's agent. Returns its
/// subject.
///
/// Only `isA`, `name` and `parent` are set, as the web app's basic "New"
/// handlers do (`BasicInstanceHandlers.ts`). A `DocumentV2` needs nothing
/// more: its editor writes the document's Loro content on the first edit.
pub async fn create_resource_of_class(
    node: &AtomicNode,
    pusher: &dyn LocalWritePusher,
    drive: &str,
    class_url: &str,
    name: &str,
) -> AtomicResult<String> {
    if drive.trim().is_empty() {
        return Err("No drive to create the resource in".into());
    }
    if class_url.trim().is_empty() {
        return Err("No class for the new resource".into());
    }
    let name = match name.trim() {
        "" => UNTITLED,
        name => name,
    };
    let store = node.db();
    let agent = store.get_default_agent()?;

    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(
        urls::IS_A.into(),
        Value::ResourceArray(vec![class_url.into()]),
    );
    builder.set(urls::NAME.into(), Value::String(name.to_string()));
    builder.set(urls::PARENT.into(), Value::AtomicUrl(drive.into()));
    let commit = Commit::create_did(builder, &agent, store).await?;
    let subject = commit.subject.to_string();
    let response = node.apply_local_commit(commit, &own_commit_opts()).await?;
    pusher.push(&response).await;
    Ok(subject)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{lists, test_support::Device, NoPush};

    #[tokio::test]
    async fn a_document_is_created_under_the_drive_by_the_device_agent() {
        let d = Device::new().await;
        let mut rx = d.store.subscribe_events();
        let subject = create_resource_of_class(
            &d.node,
            &NoPush,
            &d.drive,
            urls::DOCUMENT_V2,
            " Pelican notes ",
        )
        .await
        .unwrap();
        assert_ne!(subject, d.drive);

        let r = d
            .store
            .get_resource(&subject.as_str().into())
            .await
            .unwrap();
        assert_eq!(
            r.get(urls::IS_A).unwrap().to_subjects(None).unwrap(),
            vec![urls::DOCUMENT_V2.to_string()]
        );
        assert_eq!(r.get(urls::NAME).unwrap().to_string(), "Pelican notes");
        assert_eq!(r.get(urls::PARENT).unwrap().to_string(), d.drive);

        // Signed by this device's agent.
        let agent = d.store.get_default_agent().unwrap().subject.to_string();
        d.pump(&mut rx).await;
        let created = d
            .recents
            .activity(500)
            .into_iter()
            .find(|a| a.subject == subject)
            .expect("listed in the activity");
        assert_eq!(created.actor.as_deref(), Some(agent.as_str()));
        // The person's own work is not "activity" (that is others'), so the
        // feed leaves it out.
        let profiles = crate::host::profiles::AgentProfiles::none();
        assert!(
            lists::list_activity(&d.store, &d.recents, &profiles, None, 500)
                .await
                .iter()
                .all(|a| a.subject != subject)
        );

        // Found by search in its drive.
        let hits = lists::search(&d.store, Some(&d.drive), "pelican", 5).unwrap();
        assert!(hits.iter().any(|h| h["subject"] == subject), "{hits:?}");
    }

    #[tokio::test]
    async fn an_empty_name_becomes_untitled() {
        let d = Device::new().await;
        let subject = create_resource_of_class(&d.node, &NoPush, &d.drive, urls::FOLDER, "  ")
            .await
            .unwrap();
        let r = d
            .store
            .get_resource(&subject.as_str().into())
            .await
            .unwrap();
        assert_eq!(r.get(urls::NAME).unwrap().to_string(), UNTITLED);
    }

    #[tokio::test]
    async fn the_write_is_queued_and_pushed() {
        struct Count(std::sync::atomic::AtomicUsize);
        #[async_trait::async_trait]
        impl LocalWritePusher for Count {
            async fn push(&self, _: &crate::commit::CommitResponse) {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let d = Device::new().await;
        let pushed = Count(Default::default());
        let subject =
            create_resource_of_class(&d.node, &pushed, &d.drive, urls::DOCUMENT_V2, "Queued")
                .await
                .unwrap();
        assert_eq!(pushed.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(d.node.outbox().has_pending(&subject));
    }

    #[tokio::test]
    async fn no_drive_or_class_is_an_error() {
        let d = Device::new().await;
        assert!(
            create_resource_of_class(&d.node, &NoPush, "", urls::FOLDER, "x")
                .await
                .is_err()
        );
        assert!(
            create_resource_of_class(&d.node, &NoPush, &d.drive, "", "x")
                .await
                .is_err()
        );
    }
}
