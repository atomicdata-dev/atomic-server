//! Restore graph metadata from Vault while retaining independent file storage.
//! Requires scratch S3 configuration; writes synthetic data in a unique prefix.
//! Run: cargo run -p atomic-server --no-default-features --features light --example vault_restore_drill
use atomic_lib::{
    db::trees::Tree,
    errors::AtomicResult,
    urls,
    vault::{
        dek::DriveVaultKey,
        store::FilesystemVaultStore,
        sync::{export_vault_segment, import_vault_batch, CheckpointPolicy},
    },
    Db, Storelike, Subject, Value,
};
use std::collections::BTreeMap;

#[tokio::main(flavor = "current_thread")]
async fn main() -> AtomicResult<()> {
    let vault_dir = tempfile::Builder::new()
        .prefix("atomic-vault-restore-drill-")
        .tempdir()?
        .keep();
    let prefix = format!(
        "restore-drills/{}",
        vault_dir.file_name().unwrap().to_string_lossy()
    );
    let backend =
        || -> AtomicResult<std::sync::Arc<dyn atomic_lib::db::blob_backend::BlobBackend>> {
            atomic_server_lib::blob_storage::from_config(|name| {
                if name == "ATOMIC_S3_PREFIX" {
                    Some(prefix.clone())
                } else {
                    std::env::var(name).ok()
                }
            })?
            .ok_or_else(|| {
                "Restore drill requires ATOMIC_BLOB_BACKEND=s3 and a scratch bucket".into()
            })
        };
    let vault = FilesystemVaultStore::new(&vault_dir);
    let key = DriveVaultKey::from_bytes([7; 32], 1);
    let bytes: Vec<u8> = (0..65537).map(|i| (i % 251) as u8).collect();
    let hash = blake3::hash(&bytes);
    let mut source = Db::init_temp("restore_drill_source").await?;
    source.blob_backend = Some(backend()?);
    let (agent, drive) = source.setup("Restore drill").await?;
    let recovery_secret = agent.build_secret()?;
    let doc = source
        .create_resource(urls::DOCUMENT_V2, &drive, "Document before backup", None)
        .await?;
    let table = source
        .create_resource(urls::TABLE, &drive, "Table before backup", None)
        .await?;
    let row = source
        .create_resource(
            "https://atomicdata.dev/classes/Folder",
            &table,
            "Row before backup",
            None,
        )
        .await?;
    source.put_blob(hash.as_bytes(), &bytes).await?;
    assert!(!source.kv.contains_key(Tree::Blobs, hash.as_bytes())?);
    let file = source
        .create_resource(
            urls::FILE,
            &doc,
            "Attachment before backup",
            Some(vec![
                (urls::FILENAME, Value::String("fixture.bin".into())),
                (
                    urls::BLOB,
                    Value::AtomicUrl(format!("did:ad:blob:{}", hash.to_hex()).into()),
                ),
            ]),
        )
        .await?;
    // An independent ledger: intended contents, not values read back from source.
    let ledger = [
        (doc.clone(), "Document before backup", drive.clone()),
        (table.clone(), "Table before backup", drive.clone()),
        (row, "Row before backup", table),
        (file.clone(), "Attachment before backup", doc.clone()),
    ];
    export_vault_segment(
        &source,
        &Subject::from(drive),
        &key,
        &vault,
        "drill",
        "device",
        1,
        1,
        false,
        &BTreeMap::new(),
        CheckpointPolicy::default(),
    )
    .await?
    .ok_or("Populated fixture produced no backup")?;
    drop(source);

    let mut restored = Db::init_temp("restore_drill_empty_target").await?;
    restored.blob_backend = Some(backend()?);
    for (subject, _, _) in &ledger {
        assert!(!restored
            .kv
            .contains_key(Tree::Resources, subject.as_bytes())?);
    }
    assert!(!restored.kv.contains_key(Tree::Blobs, hash.as_bytes())?);
    let result = import_vault_batch(&restored, &key, &vault, "vault/drill/", None).await?;
    for (subject, name, parent) in &ledger {
        let resource = restored
            .get_resource(&Subject::from(subject.clone()))
            .await?;
        assert_eq!(resource.get(urls::NAME)?.to_string(), *name);
        assert_eq!(resource.get(urls::PARENT)?.to_string(), *parent);
    }
    restored.load_agent_from_secret(&recovery_secret).await?;
    let mut editable = restored.get_resource(&Subject::from(doc)).await?;
    editable.set_name("Edited after restore")?;
    editable.save_locally(&restored).await?;
    restored.flush()?;
    let restored_file = restored.get_resource(&Subject::from(file)).await?;
    assert_eq!(
        restored_file.get(urls::BLOB)?.to_string(),
        format!("did:ad:blob:{}", hash.to_hex())
    );
    // Negative controls exercise the same verification without touching existing objects.
    match std::env::var("ATOMIC_RESTORE_DRILL_FAULT").as_deref() {
        Ok("corrupt") => {
            restored
                .put_blob(hash.as_bytes(), b"corrupt fixture")
                .await?
        }
        Ok("missing") => {
            restored.blob_backend = atomic_server_lib::blob_storage::from_config(|name| {
                if name == "ATOMIC_S3_PREFIX" {
                    Some(format!("{prefix}/missing"))
                } else {
                    std::env::var(name).ok()
                }
            })?;
        }
        Ok(_) => return Err("Unknown ATOMIC_RESTORE_DRILL_FAULT".into()),
        Err(_) => {}
    }
    let recovered_bytes = restored.get_blob(hash.as_bytes()).await?;
    assert!(!restored.kv.contains_key(Tree::Blobs, hash.as_bytes())?);
    let attachment_matches = recovered_bytes
        .as_deref()
        .is_some_and(|b| blake3::hash(b) == hash);
    let complete = attachment_matches && result.objects_unreadable == 0;
    println!(
        "{}",
        serde_json::json!({
            "vault_directory": vault_dir,
            "blob_backend": "s3",
            "fixture_prefix": prefix,
            "recovery_scope": "metadata_restore_with_retained_external_files",
            "resources_checked": ledger.len(), "restored_resource_editable": true,
            "attachment_expected_blake3": hash.to_hex().to_string(),
            "attachment_bytes": bytes.len(), "attachment_matches": attachment_matches,
            "objects_unreadable": result.objects_unreadable, "complete": complete,
        })
    );
    if !complete {
        return Err("Restore incomplete: attachment bytes are missing or corrupt".into());
    }
    Ok(())
}
