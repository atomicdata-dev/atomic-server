use super::*;

#[cfg(test)]
mod drive_mapping_tests {
    use super::*;
    use crate::{test_utils::setup_test_env, Value};

    fn desired(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(h, d)| (h.to_string(), d.to_string()))
            .collect()
    }

    /// The reconcile a managed node runs on every policy poll: new names are
    /// installed, a repointed name follows its Drive, and a released name
    /// stops resolving. All three without an operator touching the box.
    #[tokio::test]
    async fn reconcile_adds_updates_and_removes() {
        let store = Db::init_temp("drive_mapping_reconcile").await.unwrap();

        let report = store
            .sync_drive_mappings(&desired(&[
                ("acme.example.com", "did:ad:acme"),
                ("blog.example.com", "did:ad:blog"),
            ]))
            .unwrap();
        assert_eq!(report.added, vec!["acme.example.com", "blog.example.com"]);
        assert!(report.updated.is_empty());
        assert!(report.removed.is_empty());

        // `acme` is repointed at another Drive (a migration), `blog` is
        // released, and `docs` is new.
        let report = store
            .sync_drive_mappings(&desired(&[
                ("acme.example.com", "did:ad:acme-moved"),
                ("docs.example.com", "did:ad:docs"),
            ]))
            .unwrap();
        assert_eq!(report.added, vec!["docs.example.com"]);
        assert_eq!(report.updated, vec!["acme.example.com"]);
        assert_eq!(report.removed, vec!["blog.example.com"]);

        assert_eq!(
            store
                .get_drive_did("acme.example.com")
                .await
                .unwrap()
                .unwrap()
                .as_str(),
            "did:ad:acme-moved"
        );
        assert!(store
            .get_drive_did("blog.example.com")
            .await
            .unwrap()
            .is_none());
    }

    /// Polled on a timer, so an unchanged policy must be a no-op rather than a
    /// write per tick.
    #[tokio::test]
    async fn reconcile_is_idempotent() {
        let store = Db::init_temp("drive_mapping_idempotent").await.unwrap();
        let want = desired(&[("acme.example.com", "did:ad:acme")]);

        assert_eq!(
            store.sync_drive_mappings(&want).unwrap().added,
            vec!["acme.example.com"]
        );
        for _ in 0..3 {
            assert!(store.sync_drive_mappings(&want).unwrap().is_empty());
        }
    }

    /// The reconcile owns only what it installed. `setup_test_env` binds
    /// `localhost` and `127.0.0.1`, and an operator may have bound a host by
    /// hand through `/bind-drive`; treating the control plane's list as
    /// authoritative for the whole table would delete all of those on the
    /// first poll.
    #[tokio::test]
    async fn reconcile_leaves_bindings_it_did_not_install_alone() {
        let store = Db::init_temp("drive_mapping_scope").await.unwrap();
        setup_test_env(&store).await.unwrap();
        let local_drive = store.get_drive_did("localhost").await.unwrap().unwrap();

        store
            .add_drive_mapping(
                "hand-bound.example.com",
                &Value::AtomicUrl("did:ad:hand-bound".into()),
            )
            .unwrap();

        let report = store
            .sync_drive_mappings(&desired(&[("acme.example.com", "did:ad:acme")]))
            .unwrap();
        assert!(report.removed.is_empty());

        // Both survive a reconcile that names neither.
        assert_eq!(
            store.get_drive_did("localhost").await.unwrap().unwrap(),
            local_drive
        );
        assert!(store
            .get_drive_did("hand-bound.example.com")
            .await
            .unwrap()
            .is_some());
    }

    /// A vanity name the control plane routed here is a host this server
    /// answers for, whatever suffix it sits under; a released one is not.
    #[tokio::test]
    async fn mapped_hosts_are_served_here() {
        let store = Db::init_temp("drive_mapping_served").await.unwrap();
        assert!(!store.has_drive_mapping("ontola.atomic.place"));

        store
            .sync_drive_mappings(&desired(&[("ontola.atomic.place", "did:ad:ontola")]))
            .unwrap();
        assert!(store.has_drive_mapping("ontola.atomic.place"));
        assert!(store.has_drive_mapping("Ontola.Atomic.Place"));
        assert!(!store.has_drive_mapping("evil.atomic.place"));
        assert!(!store.has_drive_mapping(""));

        store.sync_drive_mappings(&desired(&[])).unwrap();
        assert!(!store.has_drive_mapping("ontola.atomic.place"));
    }

    /// Hostnames are case-insensitive, but the `Host` header is echoed in
    /// whatever case the client sent. Without normalization a request for
    /// `ACME.example.com` misses the mapping and falls through to the store
    /// root.
    #[tokio::test]
    async fn mapping_keys_are_case_insensitive() {
        let store = Db::init_temp("drive_mapping_case").await.unwrap();

        store
            .sync_drive_mappings(&desired(&[("ACME.Example.COM", "did:ad:acme")]))
            .unwrap();

        for spelling in ["acme.example.com", "ACME.EXAMPLE.COM", "Acme.Example.Com"] {
            assert_eq!(
                store
                    .get_drive_did(spelling)
                    .await
                    .unwrap()
                    .unwrap_or_else(|| panic!("{spelling} should resolve"))
                    .as_str(),
                "did:ad:acme",
            );
        }

        assert_eq!(
            store.list_drive_mappings().unwrap(),
            vec![("acme.example.com".to_string(), "did:ad:acme".to_string())]
        );
    }

    /// A host with no Drive, or a Drive with no host, is a bug upstream. Both
    /// are skipped rather than written: the empty key would match no request,
    /// and an empty Drive would point a live hostname at nothing.
    #[tokio::test]
    async fn reconcile_skips_empty_hosts_and_drives() {
        let store = Db::init_temp("drive_mapping_empty").await.unwrap();

        let report = store
            .sync_drive_mappings(&desired(&[
                ("", "did:ad:nohost"),
                ("nodrive.example.com", "   "),
                ("good.example.com", "did:ad:good"),
            ]))
            .unwrap();

        assert_eq!(report.added, vec!["good.example.com"]);
        assert_eq!(
            store.list_drive_mappings().unwrap(),
            vec![("good.example.com".to_string(), "did:ad:good".to_string())]
        );
    }
}
