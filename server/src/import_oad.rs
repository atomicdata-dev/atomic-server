//! Thin host for Reflector's OpenAPI/overlay importer.
use std::{path::Path, sync::Arc};

use anyhow::{ensure, Context, Result};
use reflector_rs::{AtomicStorage, Config, ReqwestFetch, SubjectMapper};
use syncables::{ClientConfig, SyncClient};

/// Import once into the server's store without starting HTTP or background services.
pub async fn run(store_path: &Path, uploads_path: &Path, origin: &str) -> Result<()> {
    let root = std::env::var_os("REFLECTOR_ROOT")
        .map(std::path::PathBuf::from)
        .map(Ok)
        .unwrap_or_else(std::env::current_dir)?;
    let config = Config::from_env(&root)?;
    config.validate()?;
    ensure!(config.public_url == origin, "PUBLIC_URL must match the server origin ({origin}); configure --domain, --port and --https accordingly");
    let credentials =
        reflector_rs::oauth::resolve_credentials(&config.credentials, config.oauth.as_ref())
            .await
            .context("resolving API credentials")?;
    let client = SyncClient::new(
        ClientConfig {
            document: config.openapi_document,
            overlays: config.openapi_overlays,
            credentials,
            constants: config.constants,
            ontology_base_url: config.public_url.clone(),
        },
        Arc::new(ReqwestFetch::new()),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let store = Arc::new(
        atomic_lib::Db::init_redb_file(store_path, Some(origin.to_owned()), uploads_path)
            .await
            .with_context(|| {
                format!(
                    "opening {}; stop AtomicServer first (redb requires exclusive access)",
                    store_path.display()
                )
            })?,
    );
    let storage = AtomicStorage::new(store.clone(), SubjectMapper::new(config.public_url))
        .with_drive_owner(config.drive_owner);
    let result = client.sync(&storage).await;
    // Reflector persists partial progress too; index it even if a later page fails.
    atomic_lib::search::build_search_index(&store)?;
    let report = result.map_err(|e| anyhow::anyhow!("{e}"))?;
    ensure!(
        report.errors.is_empty(),
        "import incomplete: {}",
        report.errors.join("; ")
    );
    println!("OAD import finished: {report:?}");
    Ok(())
}
