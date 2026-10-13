//! Integration test: destroying a File frees its bytes once garbage collection
//! runs, while a File that is still referenced keeps them.
//!
//! Run: cargo test -p atomic-server --test it blob_gc

use atomic_lib::{
    client::connected::Client, db::blob_gc::BlobGcOptions, errors::AtomicResult, Storelike,
};
use std::time::Duration;

use crate::common::{start_server_with_store, wait_for_server};

/// POST one file to `/upload?parent=…` as `agent`; returns the File's subject.
async fn upload(
    server_url: &str,
    parent: &str,
    filename: &str,
    bytes: Vec<u8>,
    agent: &atomic_lib::agents::Agent,
) -> AtomicResult<String> {
    let url = format!("{server_url}/upload?parent={}", urlencoding::encode(parent));
    let headers = atomic_lib::client::get_authentication_headers(&url, agent)?;
    let form = reqwest::multipart::Form::new().part(
        "file",
        reqwest::multipart::Part::bytes(bytes).file_name(filename.to_string()),
    );
    let mut req = reqwest::Client::new().post(&url).multipart(form);
    for (k, v) in headers {
        req = req.header(k, v);
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("upload returned {status}: {body}").into());
    }
    let created: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    Ok(created[0]["@id"]
        .as_str()
        .ok_or("upload response has no @id")?
        .to_string())
}

async fn download_status(server_url: &str, hash_hex: &str) -> u16 {
    reqwest::get(format!("{server_url}/download/files/{hash_hex}"))
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn destroyed_file_frees_its_blob_and_referenced_file_survives() -> AtomicResult<()> {
    // The background sweep is off: this test decides when GC runs.
    let (port, store) = start_server_with_store("blob_gc", &["--blob-gc-interval", "off"]);
    wait_for_server(port).await;
    let server_url = format!("http://localhost:{port}");

    let client = Client::new(&server_url).await?;
    let agent = client.new_agent("Alice").await?;
    let drive = client.new_public_drive(&agent, "GC Drive").await?;

    let doomed_bytes = b"this file is destroyed and its bytes must go".to_vec();
    let kept_bytes = b"this file stays and so do its bytes".to_vec();
    let doomed_hash = blake3::hash(&doomed_bytes).to_hex().to_string();
    let kept_hash = blake3::hash(&kept_bytes).to_hex().to_string();

    let doomed = upload(&server_url, &drive, "doomed.txt", doomed_bytes, &agent).await?;
    upload(&server_url, &drive, "kept.txt", kept_bytes, &agent).await?;
    assert_eq!(download_status(&server_url, &doomed_hash).await, 200);
    assert_eq!(download_status(&server_url, &kept_hash).await, 200);

    // Destroy the first File on the server, the way a destroy commit does.
    // Looked up by `internalId` because the stored subject of an upload is
    // an internal one, not the URL the upload response shows.
    let stored = store
        .query(&atomic_lib::storelike::Query::new_prop_val(
            atomic_lib::urls::INTERNAL_ID,
            &doomed_hash,
        ))
        .await?
        .resources;
    assert_eq!(stored.len(), 1, "{doomed}");
    store.remove_resource(stored[0].get_subject()).await?;

    // Destroying a File frees no storage by itself: that is the bug.
    assert_eq!(download_status(&server_url, &doomed_hash).await, 200);

    // A dry run names the orphan and deletes nothing.
    let dry = store
        .gc_blobs(&BlobGcOptions::new(Duration::ZERO).dry_run(true))
        .await?;
    let candidates: Vec<_> = dry.candidates.iter().map(|c| hex::encode(&c.key)).collect();
    assert_eq!(candidates, vec![doomed_hash.clone()]);
    assert_eq!(download_status(&server_url, &doomed_hash).await, 200);

    // The default grace period protects bytes that were only just written.
    let report = store
        .gc_blobs(&BlobGcOptions::new(Duration::from_secs(72 * 3600)))
        .await?;
    assert_eq!(report.deleted, 0);
    assert_eq!(download_status(&server_url, &doomed_hash).await, 200);

    // Past the grace period (zero here) the orphan goes and the rest stays.
    let report = store.gc_blobs(&BlobGcOptions::new(Duration::ZERO)).await?;
    assert_eq!(report.deleted, 1);
    assert_eq!(
        report.deleted_bytes,
        b"this file is destroyed and its bytes must go".len() as u64
    );
    assert_eq!(download_status(&server_url, &doomed_hash).await, 404);
    assert_eq!(download_status(&server_url, &kept_hash).await, 200);

    Ok(())
}
