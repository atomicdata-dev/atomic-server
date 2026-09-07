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
    for platform in &config.platforms {
        let credentials = if platform.name == "github" {
            reflector_rs::oauth::resolve_credentials(&platform.credentials, config.oauth.as_ref())
                .await
                .context("resolving API credentials")?
        } else {
            platform.credentials.clone()
        };
        let client = SyncClient::new(
            ClientConfig {
                document: platform.openapi_document.clone(),
                overlays: platform.openapi_overlays.clone(),
                credentials,
                constants: platform.constants.clone(),
                ontology_base_url: config.public_url.clone(),
            },
            Arc::new(ReqwestFetch::new()),
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        let storage =
            AtomicStorage::new(store.clone(), SubjectMapper::new(config.public_url.clone()))
                .with_drive_owner(config.drive_owner.clone())
                .with_dataset(platform.dataset_namespace());
        let result = client.sync(&storage).await;
        atomic_lib::search::build_search_index(&store)?;
        let report = result.map_err(|e| anyhow::anyhow!("{e}"))?;
        ensure!(
            report.errors.is_empty(),
            "import incomplete: {}",
            report.errors.join("; ")
        );
        println!("OAD import finished: {report:?}");
    }
    Ok(())
}
