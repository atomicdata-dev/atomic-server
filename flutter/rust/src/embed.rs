//! The embedded renderer's calls, answered by `atomic_lib::host::embed` from
//! the store `open_db` opened. What the page may have signed, and how its
//! commits are applied, is decided there; here a commit the page applied is
//! pushed on like any other local write of this app.

use crate::api::simple::state::node;

/// One call from the page.
pub(crate) async fn call(method: &str, args_json: &str) -> Result<String, String> {
    atomic_lib::host::embed::EmbedHost::new(node()?, crate::host::pusher(), crate::host::profiles())
        .call(method, args_json)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::simple::{state::db, tests::shared_drive};
    use atomic_lib::{urls, Storelike, Subject};
    use serde_json::{json, Value as Json};

    async fn ask(method: &str, args: Json) -> Json {
        serde_json::from_str(&call(method, &args.to_string()).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn the_page_can_read_a_resource_under_either_spelling() {
        let drive = shared_drive().await;
        let folder = db()
            .unwrap()
            .create_resource(urls::FOLDER, drive, "Embed folder", None)
            .await
            .unwrap();
        let other_spelling = if folder.starts_with("atomic:") {
            folder.replacen("atomic:", "did:ad:", 1)
        } else {
            folder.replacen("did:ad:", "atomic:", 1)
        };

        let rows = ask(
            "getResourcesWithSnapshots",
            json!([[folder, other_spelling, "did:ad:not-here"]]),
        )
        .await;
        let rows = rows.as_array().unwrap();

        for row in &rows[..2] {
            assert!(row["jsonAd"].as_str().unwrap().contains("Embed folder"));
            assert!(!row["snapshot"].as_str().unwrap().is_empty());
        }
        // Answered under the name it was asked by.
        assert!(rows[1]["jsonAd"]
            .as_str()
            .unwrap()
            .contains(&other_spelling));
        assert!(rows[2]["jsonAd"].is_null());
    }

    /// Bytes in a commit's `loroUpdate` are standard, padded base64, as the
    /// page's `encodeB64` writes them.
    fn standard_base64(bytes: &[u8]) -> String {
        let url_safe = atomic_lib::agents::encode_base64(bytes)
            .replace('-', "+")
            .replace('_', "/");
        let pad = (4 - url_safe.len() % 4) % 4;
        format!("{url_safe}{}", "=".repeat(pad))
    }

    /// The page's save path through the bridge: a commit signed with `sign`,
    /// handed over with `applyCommit`, is in the store and queued for sync.
    /// The signing policy and the other calls are tested in
    /// `atomic_lib::host::embed`.
    #[tokio::test]
    async fn a_typed_edit_to_a_document_is_there_when_it_is_opened_again() {
        use atomic_lib::loro::AtomicLoroDoc;
        let drive = shared_drive().await;
        let store = db().unwrap();
        let doc_subject = store
            .create_resource(urls::DOCUMENT_V2, drive, "Typed doc", None)
            .await
            .unwrap();
        let subject = Subject::from_raw(&doc_subject, store.get_base_domain().as_deref());

        // The page's view of the document, as it opened it.
        let opened = ask("getResourcesWithSnapshots", json!([[doc_subject]])).await;
        let snapshot =
            atomic_lib::agents::decode_base64(opened[0]["snapshot"].as_str().unwrap()).unwrap();
        let page_doc = AtomicLoroDoc::from_snapshot(&snapshot).unwrap();
        page_doc.set_peer_id(0x5eed).unwrap();
        let before = page_doc.oplog_vv();
        page_doc
            .doc()
            .get_text("documentContent")
            .insert(0, "Quokkatyped on the phone")
            .unwrap();
        page_doc.commit_with_message("e-typing");
        let update = page_doc.export_updates_since(&before);

        let agent = ask("agent", json!([])).await;
        let previous = store
            .get_resource(&subject)
            .await
            .unwrap()
            .get(urls::LAST_COMMIT)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "did:ad:commit:earlier".to_string());
        let mut commit = json!({
            urls::IS_A: [urls::COMMIT],
            urls::SUBJECT: doc_subject,
            urls::SIGNER: agent,
            urls::CREATED_AT: atomic_lib::utils::now(),
            urls::PREVIOUS_COMMIT: previous,
            urls::LORO_UPDATE: standard_base64(&update),
        });
        let signature = ask("sign", json!([commit.to_string()])).await;
        commit[urls::SIGNATURE] = signature;

        assert_eq!(
            ask("applyCommit", json!([commit.to_string()])).await,
            Json::Null
        );

        let reopened = ask("getResourcesWithSnapshots", json!([[doc_subject]])).await;
        let snapshot =
            atomic_lib::agents::decode_base64(reopened[0]["snapshot"].as_str().unwrap()).unwrap();
        let text = AtomicLoroDoc::from_snapshot(&snapshot)
            .unwrap()
            .extract_document_plain_text();
        assert!(text.contains("Quokkatyped on the phone"), "{text:?}");
        assert!(
            node().unwrap().outbox().has_pending(&subject.pure_id()),
            "the edit is queued for sync"
        );
    }
}
