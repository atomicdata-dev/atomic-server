use actix_web::{web, HttpResponse};
use atomic_lib::{storelike::Query, urls, Db, Storelike, Value};

use crate::errors::{AppErrorType, AtomicServerError};
use crate::{appstate::AppState, errors::AtomicServerResult};

/// F4 follow-up (planning/unified-sync.md): resolve write-admission for a
/// blob PUT. `Ok(())` iff some resource on this server already references
/// `did:ad:blob:<hash_hex>` via the `BLOB` property, and that resource's
/// drive passes `admit_drive_write`. Pulled out of the HTTP handler so it's
/// unit-testable directly against a `Db` — there's no config-level way to
/// spin up the actix server with a non-default `SyncPolicy` installed
/// (policies are installed programmatically by an embedder, not via CLI
/// flags), so an actix-integration test can't exercise the rejection paths.
async fn resolve_blob_write_admission(store: &Db, hash_hex: &str) -> Result<(), String> {
    let blob_subject = format!("did:ad:blob:{hash_hex}");

    let mut q = Query::new();
    q.property = Some(urls::BLOB.to_string());
    q.value = Some(Value::AtomicUrl(blob_subject.into()));
    let result = store.query(&q).await.map_err(|e| e.to_string())?;

    if result.resources.is_empty() {
        return Err(format!(
            "No resource references did:ad:blob:{hash_hex} yet — post the commit that \
             references it before pushing its bytes."
        ));
    }

    // Content-addressed bytes can legitimately be referenced from resources
    // in more than one drive (e.g. the same file uploaded independently into
    // two drives). Accept if ANY referencing resource's drive is admitted —
    // that drive genuinely wants these bytes, regardless of whether some
    // other, unrelated drive also happens to reference the same hash. A
    // single-result `limit` here would make the verdict depend on iteration
    // order instead of on the actual admission question.
    let admitted = result.resources.iter().any(|referencing| {
        let drive = referencing
            .get(urls::DRIVE_PROP)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| referencing.get_subject().to_string());
        store.sync_policy().admit_drive_write(&drive)
    });

    if !admitted {
        return Err(format!(
            "did:ad:blob:{hash_hex} is referenced, but no referencing drive is admitted for writes"
        ));
    }

    Ok(())
}

/// HTTP fallback for pushing blob bytes to the server. Used by clients when
/// the WebSocket BLOB_RESPONSE path isn't available (WS not open, restricted
/// network, etc.). The hash is verified server-side: a body whose BLAKE3
/// digest doesn't match the URL hash is rejected.
///
/// F4 follow-up (planning/unified-sync.md): the hash alone is NOT the
/// capability — an attacker choosing their own bytes can always compute a
/// matching hash for them, so hash-verification alone gates nothing. Bytes
/// are only accepted when a resource *already on this server* references
/// `did:ad:blob:<hash>` via the `BLOB` property, and that resource's drive
/// passes `admit_drive_write` — mirrors the WS `BLOB_RESPONSE` gate
/// (`sync::engine::handle_frame`), just keyed by "a matching commit already
/// landed" instead of "we issued a matching `BLOB_REQUEST`". The client's
/// outbox drain POSTs the commit (creating that reference) before pushing
/// the blob, so ordering works: see `local-outbox.ts`.
#[tracing::instrument(skip(appstate, body))]
pub async fn put_blob(
    path: web::Path<String>,
    appstate: web::Data<AppState>,
    body: web::Bytes,
) -> AtomicServerResult<HttpResponse> {
    let hash_hex = path.into_inner();
    if hash_hex.len() != 64 {
        return Err("Hash must be 64 hex chars (BLAKE3)".into());
    }
    let hash_bytes = hex::decode(&hash_hex).map_err(|_| "Hash must be valid hex".to_string())?;

    let computed = blake3::hash(&body);
    if computed.as_bytes() != hash_bytes.as_slice() {
        return Err(format!(
            "Body hash {} does not match URL hash {}",
            computed.to_hex(),
            hash_hex
        )
        .into());
    }

    let store = &appstate.store;

    if let Err(message) = resolve_blob_write_admission(store, &hash_hex).await {
        return Err(AtomicServerError {
            message,
            error_type: AppErrorType::Unauthorized,
            error_resource: None,
        });
    }

    store.put_blob(&hash_bytes, &body).await?;

    Ok(HttpResponse::NoContent().finish())
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use atomic_lib::sync::policy::AllowlistPolicy;
    use std::sync::Arc;
    use std::time::Duration;

    /// F4 follow-up: a hash with no referencing resource must be rejected —
    /// otherwise the hash alone is the write capability, and an attacker can
    /// always compute a hash for bytes of their own choosing.
    #[tokio::test]
    async fn unreferenced_hash_is_rejected() {
        let db = Db::init_temp("blob_admission_unreferenced").await.unwrap();
        let _ = db.setup("Alice").await.unwrap();

        let hash_hex = blake3::hash(b"nobody committed a reference to this")
            .to_hex()
            .to_string();

        let err = resolve_blob_write_admission(&db, &hash_hex)
            .await
            .expect_err("a hash with no referencing resource must be rejected");
        assert!(
            err.contains("No resource references"),
            "unexpected error message: {err}"
        );
    }

    /// Companion: once a resource legitimately references the hash (the
    /// commit landed first, matching the outbox drain's ordering) and its
    /// drive is admitted, the write is allowed.
    #[tokio::test]
    async fn referenced_hash_on_admitted_drive_is_allowed() {
        let db = Db::init_temp("blob_admission_referenced_admitted")
            .await
            .unwrap();
        let (_alice, drive) = db.setup("Alice").await.unwrap();

        let hash_hex = blake3::hash(b"legitimate upload bytes")
            .to_hex()
            .to_string();
        let subject = db
            .create_resource(
                "https://atomicdata.dev/classes/Folder",
                &drive,
                "a file",
                None,
            )
            .await
            .unwrap();
        let mut resource = db.get_resource(&subject.as_str().into()).await.unwrap();
        resource
            .set_unsafe(
                urls::BLOB.into(),
                atomic_lib::Value::AtomicUrl(format!("did:ad:blob:{hash_hex}").into()),
            )
            .unwrap();
        db.add_resource(&resource).await.unwrap();

        // Default policy (`OpenPolicy`, installed by `Db::init_temp`) admits
        // every drive — this is the "legit flow unaffected" case.
        resolve_blob_write_admission(&db, &hash_hex)
            .await
            .expect("a referenced hash on an admitted drive must be allowed");
    }

    /// F4 follow-up: a resource DOES reference the hash, but its drive is not
    /// admitted by the installed policy — must still be rejected. Otherwise
    /// gating only on "does a reference exist" would let a write into any
    /// drive the attacker can get a File resource created in (e.g. one they
    /// have write rights on but that a managed node hasn't enrolled/quota'd).
    #[tokio::test]
    async fn referenced_hash_on_unadmitted_drive_is_rejected() {
        let db = Db::init_temp("blob_admission_referenced_unadmitted")
            .await
            .unwrap();
        let (_alice, drive) = db.setup("Alice").await.unwrap();

        let hash_hex = blake3::hash(b"bytes for an unenrolled drive")
            .to_hex()
            .to_string();
        let subject = db
            .create_resource(
                "https://atomicdata.dev/classes/Folder",
                &drive,
                "a file",
                None,
            )
            .await
            .unwrap();
        let mut resource = db.get_resource(&subject.as_str().into()).await.unwrap();
        resource
            .set_unsafe(
                urls::BLOB.into(),
                atomic_lib::Value::AtomicUrl(format!("did:ad:blob:{hash_hex}").into()),
            )
            .unwrap();
        db.add_resource(&resource).await.unwrap();

        // Empty allowlist, no bootstrap grace: nothing is enrolled, so
        // `drive` is not admitted — matches the managed-node gate test
        // pattern in `commit.rs`.
        let policy = Arc::new(AllowlistPolicy::new());
        policy.set_grace(Duration::ZERO);
        db.set_sync_policy(policy);

        let err = resolve_blob_write_admission(&db, &hash_hex)
            .await
            .expect_err("a referenced hash on an unadmitted drive must be rejected");
        assert!(
            err.contains("no referencing drive is admitted"),
            "unexpected error message: {err}"
        );
    }

    /// F4 follow-up, second-review edge case: content-addressed bytes can
    /// legitimately be referenced from resources in more than one drive. If
    /// ANY referencing drive is admitted, the write must be allowed — the
    /// verdict must not depend on which of the several referencing resources
    /// a `limit`-ed query happens to return first.
    ///
    /// Subjects are hand-picked (not `create_resource`'s random DIDs) so the
    /// unadmitted resource is guaranteed to sort first in the property-value
    /// index (`{property}|{value}|{subject}` keys, subject-ordered among
    /// ties) — a `limit(1)`/first-result-only implementation is deterministically
    /// forced onto the unadmitted resource here, rather than merely likely to
    /// hit it. Confirmed via revert-and-check: with `Db::init_temp`'s random
    /// DIDs this test failed only ~60% of runs against the reverted logic;
    /// with these forced subjects it fails 100% of runs.
    #[tokio::test]
    async fn referenced_hash_admitted_via_any_matching_drive() {
        let db = Db::init_temp("blob_admission_any_pass").await.unwrap();
        let (_alice, admitted_drive) = db.setup("Alice").await.unwrap();
        let (_bob, unadmitted_drive) = db.setup("Bob").await.unwrap();

        let hash_hex = blake3::hash(b"same bytes, referenced from two drives")
            .to_hex()
            .to_string();

        for (subject, drive) in [
            ("/aaa-unadmitted-sorts-first", &unadmitted_drive),
            ("/zzz-admitted-sorts-last", &admitted_drive),
        ] {
            let mut resource = atomic_lib::Resource::new(subject.to_string());
            resource
                .set_unsafe(
                    urls::IS_A.into(),
                    atomic_lib::Value::ResourceArray(vec!["https://atomicdata.dev/classes/Folder"
                        .to_string()
                        .into()]),
                )
                .unwrap();
            resource
                .set_unsafe(
                    urls::NAME.into(),
                    atomic_lib::Value::String("a file".into()),
                )
                .unwrap();
            resource
                .set_unsafe(
                    urls::DRIVE_PROP.into(),
                    atomic_lib::Value::AtomicUrl(drive.clone().into()),
                )
                .unwrap();
            resource
                .set_unsafe(
                    urls::BLOB.into(),
                    atomic_lib::Value::AtomicUrl(format!("did:ad:blob:{hash_hex}").into()),
                )
                .unwrap();
            db.add_resource(&resource).await.unwrap();
        }

        // Only `admitted_drive` is enrolled; `unadmitted_drive` is not.
        let policy = Arc::new(AllowlistPolicy::new());
        policy.set_grace(Duration::ZERO);
        policy.set_drive_policies([(admitted_drive.clone(), None)]);
        db.set_sync_policy(policy);

        resolve_blob_write_admission(&db, &hash_hex).await.expect(
            "a hash referenced from one admitted drive, among several referencing drives, \
             must be allowed",
        );
    }
}
