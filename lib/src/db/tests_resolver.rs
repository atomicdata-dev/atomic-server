use super::*;

#[cfg(test)]
mod resolver_tests {
    use super::*;
    use crate::{test_utils::setup_test_env, urls, Resource, Storelike, Value};

    #[tokio::test]
    async fn resolves_root_to_drive_subject() {
        let store = Db::init_temp("resolver_root").await.unwrap();
        setup_test_env(&store).await.unwrap();

        let resolved = store
            .resolve_request_target(
                &Subject::from_raw("/", None),
                "localhost",
                "/",
                "http://localhost",
            )
            .await
            .unwrap();

        assert_eq!(
            resolved.alias_subject,
            Some("http://localhost/".to_string())
        );
        assert!(matches!(resolved.subject, Subject::Did { .. }));
    }

    #[tokio::test]
    async fn resolves_drive_relative_paths_to_canonical_did() {
        let store = Db::init_temp("resolver_path").await.unwrap();
        setup_test_env(&store).await.unwrap();

        let drive_did = store.get_drive_did("localhost").await.unwrap().unwrap();
        let mut resource = Resource::new("did:ad:test-child".into());
        resource
            .set_unsafe(urls::PARENT.into(), Value::AtomicUrl(drive_did.clone()))
            .unwrap();
        resource
            .set_unsafe(urls::SHORTNAME.into(), Value::Slug("about".into()))
            .unwrap();
        resource
            .set_unsafe(urls::NAME.into(), Value::String("About".into()))
            .unwrap();
        store
            .add_resource_opts(&resource, false, true, true)
            .await
            .unwrap();

        let resolved = store
            .resolve_request_target(
                &Subject::from_raw("/about", None),
                "localhost",
                "/about",
                "http://localhost",
            )
            .await
            .unwrap();

        assert_eq!(
            resolved.alias_subject,
            Some("http://localhost/about".to_string())
        );
        assert_eq!(
            resolved.subject.as_str(),
            "atomic:test-child?drive=".to_string() + drive_did.as_str()
        );
    }

    /// The vanity-subdomain hazard: a host is bound to a Drive this node does
    /// not hold (not synced yet, or migrated away). Serving the store root
    /// instead would answer a customer's hostname with another namespace's
    /// content, so the request must fail.
    #[tokio::test]
    async fn a_bound_host_whose_drive_is_missing_does_not_serve_the_store_root() {
        let store = Db::init_temp("resolver_missing_drive").await.unwrap();
        setup_test_env(&store).await.unwrap();
        let root_drive = store.get_drive_did("localhost").await.unwrap().unwrap();

        store
            .add_drive_mapping(
                "acme.example.com",
                &Value::AtomicUrl("did:ad:not-on-this-node".into()),
            )
            .unwrap();

        for path in ["/", "/about"] {
            let resolved = store
                .resolve_request_target(
                    &Subject::from_raw(path, None),
                    "acme.example.com",
                    path,
                    "https://acme.example.com",
                )
                .await;

            let Err(err) = resolved else {
                panic!("{path} on a bound host with a missing drive must not resolve");
            };
            assert!(
                !format!("{err}").contains(root_drive.as_str()),
                "must not leak the root drive: {err}"
            );
        }

        // The node's own hostname is unaffected: it has no mapping, so it
        // keeps serving its root as before.
        assert!(store
            .resolve_request_target(
                &Subject::from_raw("/", None),
                "node1.example.com",
                "/",
                "https://node1.example.com",
            )
            .await
            .is_ok());
    }
}
