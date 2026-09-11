//! Native instance backup. Control is opt-in, loopback-only and token-protected.
//! Capture owns the maintenance guard in the blocking worker, so cancellation
//! of an HTTP request cannot resume writers while files are still being copied.
use crate::{appstate::AppState, config::Config, errors::AtomicServerResult};
use actix_web::{web, HttpRequest, HttpResponse};
use atomic_lib::{errors::AtomicResult, Db};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};

const FORMAT: u32 = 1;
const MANIFEST: &str = "manifest.json";
const RESTORED: &str = "RESTORED_OFFLINE";
const CONTROL: &str = "/__atomic/backup";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Status {
    pub id: Option<String>,
    pub phase: String,
    pub archive: Option<PathBuf>,
    pub error: Option<String>,
}

pub struct BackupService {
    output: Option<PathBuf>,
    token: String,
    status: Mutex<Status>,
}

impl BackupService {
    pub fn new(config: &Config) -> AtomicResult<Arc<Self>> {
        let mut token = String::new();
        let output = if let Some(path) = &config.opts.backup_dir {
            if !path.exists() {
                let mut builder = fs::DirBuilder::new();
                builder.recursive(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder.create(path)?;
            }
            // Existing destinations may be shared directories. Never chmod
            // them; staging directories and final ZIP files are owner-only.
            let output = path.canonicalize()?;
            let data = data_dir(config)?.canonicalize()?;
            let configuration = config.config_dir.canonicalize()?;
            if data.starts_with(&configuration) || configuration.starts_with(&data) {
                return Err("Instance backup requires separate, non-overlapping data and config directories".into());
            }
            for source in [data_dir(config)?, config.config_dir.clone()] {
                let source = source.canonicalize()?;
                if output.starts_with(&source) || source.starts_with(&output) {
                    return Err(
                        "Backup directory must be outside data and config directories".into(),
                    );
                }
            }
            // Vector-index flush runs independently and is deliberately not
            // backed up. Require cache storage outside the capture roots.
            for cache in [&config.vector_search_index_path, &config.plugin_cache_path] {
                let cache = resolve_future_path(cache)?;
                if cache.starts_with(data_dir(config)?.canonicalize()?)
                    || cache.starts_with(config.config_dir.canonicalize()?)
                {
                    return Err(
                        "Instance backup requires --cache-dir outside data and config directories"
                            .into(),
                    );
                }
            }
            let token_path = config.config_dir.join("backup.token");
            if token_path.exists() {
                if fs::symlink_metadata(&token_path)?.file_type().is_symlink() {
                    return Err("Backup token must not be a symlink".into());
                }
                token = fs::read_to_string(&token_path)?.trim().to_owned();
                if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err("Invalid backup.token; expected 64 hexadecimal characters".into());
                }
                private_file(&token_path)?;
            } else {
                // Agent creation uses the same cryptographic RNG as server identities.
                token = blake3::hash(
                    atomic_lib::agents::Agent::new(None)?
                        .private_key
                        .ok_or("Missing generated private key")?
                        .as_bytes(),
                )
                .to_hex()
                .to_string();
                let mut file = create_private(&token_path)?;
                file.write_all(token.as_bytes())?;
                file.sync_all()?;
            }
            Some(output)
        } else {
            None
        };
        Ok(Arc::new(Self {
            output,
            token,
            status: Mutex::new(Status {
                phase: "idle".into(),
                ..Default::default()
            }),
        }))
    }

    fn authorized(&self, request: &HttpRequest) -> bool {
        self.output.is_some()
            && request.peer_addr().is_some_and(|p| p.ip().is_loopback())
            && request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .is_some_and(|token| {
                    blake3::hash(token.as_bytes()) == blake3::hash(self.token.as_bytes())
                })
    }

    fn phase(&self, phase: &str) {
        self.status.lock().unwrap().phase = phase.into();
    }
}

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource(CONTROL)
            .route(web::post().to(start))
            .route(web::get().to(status)),
    );
}

async fn status(request: HttpRequest, app: web::Data<AppState>) -> HttpResponse {
    if !app.backup.authorized(&request) {
        return HttpResponse::Unauthorized().finish();
    }
    HttpResponse::Ok().json(app.backup.status.lock().unwrap().clone())
}

async fn start(request: HttpRequest, app: web::Data<AppState>) -> HttpResponse {
    if !app.backup.authorized(&request) {
        return HttpResponse::Unauthorized().finish();
    }
    let service = app.backup.clone();
    let id = format!(
        "{}-{}",
        chrono::Utc::now().format("%Y-%m-%dT%H%M%S%.3fZ"),
        std::process::id()
    );
    {
        let mut state = service.status.lock().unwrap();
        if !matches!(state.phase.as_str(), "idle" | "complete" | "failed") {
            return HttpResponse::Conflict().json(state.clone());
        }
        *state = Status {
            id: Some(id.clone()),
            phase: "draining".into(),
            ..Default::default()
        };
    }
    let store = app.store.clone();
    let config = app.config.clone();
    let job_id = id.clone();
    // Detached from the caller; the worker, not an HTTP connection, owns cleanup.
    tokio::spawn(async move {
        let result = run_backup(&store, &config, &service, &job_id).await;
        let mut state = service.status.lock().unwrap();
        match result {
            Ok(path) => {
                state.phase = "complete".into();
                state.archive = Some(path);
            }
            Err(error) => {
                state.phase = "failed".into();
                state.error = Some(error.to_string());
            }
        }
    });
    HttpResponse::Accepted().json(Status {
        id: Some(id),
        phase: "draining".into(),
        ..Default::default()
    })
}

async fn run_backup(
    store: &Db,
    config: &Config,
    service: &Arc<BackupService>,
    id: &str,
) -> AtomicResult<PathBuf> {
    let pause = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        store.maintenance.pause(),
    )
    .await
    .map_err(|_| "Timed out draining operations; server resumed")?
    .map_err(|e| e.to_string())?;
    let store = store.clone();
    let config = config.clone();
    let service = service.clone();
    let id = id.to_owned();
    tokio::task::spawn_blocking(move || {
        service.phase("capturing");
        let output = service.output.as_ref().ok_or("Backups disabled")?;
        let staging = tempfile::Builder::new()
            .prefix(".atomic-backup-")
            .tempdir_in(output)?;
        let captured = capture(&store, &config, staging.path());
        // Also runs on capture errors. During a panic RAII unwinds this guard.
        drop(pause);
        captured?;
        service.phase("archiving");
        archive(staging.path(), output, &id)
    })
    .await
    .map_err(|e| format!("Backup worker failed: {e}"))?
}

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    format: u32,
    server_version: String,
    build_revision: String,
    redb_version: String,
    snapshot_time: String,
    freshness: String,
    envelope_retention: String,
    source_data: PathBuf,
    source_config: PathBuf,
    files: BTreeMap<String, Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    bytes: u64,
    blake3: String,
}

// Canonicalize an existing ancestor, then append not-yet-created components.
fn resolve_future_path(path: &Path) -> AtomicResult<PathBuf> {
    if path.exists() {
        return Ok(path.canonicalize()?);
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(resolve_future_path(parent)?.join(path.file_name().ok_or("Invalid storage path")?))
}

fn data_dir(config: &Config) -> AtomicResult<PathBuf> {
    Ok(config
        .store_path
        .parent()
        .ok_or("Store has no parent")?
        .to_path_buf())
}

fn capture(store: &Db, config: &Config, stage: &Path) -> AtomicResult<()> {
    let source_data = data_dir(config)?.canonicalize()?;
    let source_config = config.config_dir.canonicalize()?;
    let db_path = stage.join("data/store/atomic.redb");
    fs::create_dir_all(db_path.parent().unwrap())?;
    let mut snapshot_time = String::new();
    store.kv.backup_snapshot(&db_path, &mut || {
        snapshot_time = chrono::Utc::now().to_rfc3339();
        copy_tree(
            &source_data,
            &stage.join("data"),
            Some(Path::new("store/atomic.redb")),
        )?;
        copy_tree(&source_config, &stage.join("config"), None)?;
        Ok(())
    })?;
    let mut files = BTreeMap::new();
    inventory(stage, stage, &mut files)?;
    let manifest = Manifest {
        format: FORMAT,
        server_version: env!("CARGO_PKG_VERSION").into(),
        build_revision: env!("ATOMIC_BACKUP_REVISION").into(),
        redb_version: "4.1.0".into(),
        snapshot_time,
        freshness: "Local persisted checkpoint; remote replication completeness is not asserted"
            .into(),
        envelope_retention: store.envelope_retention().as_str().into(),
        source_data,
        source_config,
        files,
    };
    fs::write(stage.join(MANIFEST), serde_json::to_vec_pretty(&manifest)?)?;
    Ok(())
}

fn copy_tree(source: &Path, target: &Path, exclude: Option<&Path>) -> AtomicResult<()> {
    fs::create_dir_all(target)?;
    for item in fs::read_dir(source)? {
        let item = item?;
        let rel = PathBuf::from(item.file_name());
        if exclude == Some(rel.as_path()) {
            continue;
        }
        let ty = item.file_type()?;
        let dest = target.join(&rel);
        if ty.is_symlink() {
            return Err(format!("Refusing symlink in backup: {}", item.path().display()).into());
        }
        if ty.is_dir() {
            let nested = exclude.and_then(|p| p.strip_prefix(&rel).ok());
            copy_tree(&item.path(), &dest, nested)?;
        } else if ty.is_file() {
            let before = item.metadata()?;
            fs::copy(item.path(), &dest)?;
            let after = item.metadata()?;
            if before.len() != after.len() || before.modified()? != after.modified()? {
                return Err(
                    format!("File changed during backup: {}", item.path().display()).into(),
                );
            }
            private_file(&dest)?;
        } else {
            return Err(format!("Unsupported backup file: {}", item.path().display()).into());
        }
    }
    Ok(())
}

fn digest(path: &Path) -> AtomicResult<Entry> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 65536];
    let mut bytes = 0;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        bytes += n as u64;
    }
    Ok(Entry {
        bytes,
        blake3: hasher.finalize().to_hex().to_string(),
    })
}

fn inventory(root: &Path, dir: &Path, files: &mut BTreeMap<String, Entry>) -> AtomicResult<()> {
    for item in fs::read_dir(dir)? {
        let item = item?;
        if item.file_type()?.is_dir() {
            inventory(root, &item.path(), files)?;
        } else {
            let path = item.path();
            let name = path
                .strip_prefix(root)
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or("Non-UTF8 backup path")?
                .replace('\\', "/");
            files.insert(name, digest(&path)?);
        }
    }
    Ok(())
}

fn archive(stage: &Path, output: &Path, id: &str) -> AtomicResult<PathBuf> {
    use zip::write::SimpleFileOptions;
    let manifest: Manifest = serde_json::from_reader(File::open(stage.join(MANIFEST))?)?;
    let mut temp = tempfile::NamedTempFile::new_in(output)?;
    {
        let mut writer = zip::ZipWriter::new(temp.as_file_mut());
        for name in manifest
            .files
            .keys()
            .map(String::as_str)
            .chain(std::iter::once(MANIFEST))
        {
            let path = stage.join(name);
            let options = SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(0o600)
                .large_file(fs::metadata(&path)?.len() >= u32::MAX as u64);
            writer
                .start_file(name, options)
                .map_err(|e| e.to_string())?;
            std::io::copy(&mut File::open(path)?, &mut writer)?;
        }
        writer.finish().map_err(|e| e.to_string())?;
    }
    temp.as_file().sync_all()?;
    // Read back the ZIP and every hash before publication, without extracting.
    verify_archive(temp.path())?;
    let path = output.join(format!("atomic-backup-{id}.zip"));
    temp.persist_noclobber(&path).map_err(|e| e.to_string())?;
    File::open(output)?.sync_all()?;
    Ok(path)
}

fn safe_name(name: &str) -> bool {
    !name.contains('\\')
        && !name.contains(':')
        && !name.contains('\0')
        && Path::new(name)
            .components()
            .all(|p| matches!(p, Component::Normal(_)))
        && (name.starts_with("data/") || name.starts_with("config/"))
}

fn verify_archive(path: &Path) -> AtomicResult<Manifest> {
    let mut zip = zip::ZipArchive::new(File::open(path)?).map_err(|e| e.to_string())?;
    let manifest: Manifest = {
        let mut file = zip.by_name(MANIFEST).map_err(|e| e.to_string())?;
        if file.size() > 16 * 1024 * 1024 {
            return Err("Oversized backup manifest".into());
        }
        let mut json = Vec::new();
        file.read_to_end(&mut json)?;
        serde_json::from_slice(&json)?
    };
    if manifest.format != FORMAT {
        return Err("Unsupported backup format".into());
    }
    if manifest.server_version != env!("CARGO_PKG_VERSION") {
        return Err(format!("Restore requires atomic-server {}", manifest.server_version).into());
    }
    if !manifest.files.contains_key("data/store/atomic.redb")
        || !manifest.files.contains_key("config/config.toml")
    {
        return Err("Backup lacks database or identity configuration".into());
    }
    if zip.len() != manifest.files.len() + 1 {
        return Err("Unexpected or duplicate archive entries".into());
    }
    let mut seen = std::collections::HashSet::new();
    for i in 0..zip.len() {
        let mut file = zip.by_index(i).map_err(|e| e.to_string())?;
        let name = file.name().to_owned();
        if !seen.insert(name.clone()) {
            return Err("Duplicate archive path".into());
        }
        if name == MANIFEST {
            continue;
        }
        if !safe_name(&name)
            || file.is_dir()
            || file.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000)
        {
            return Err(format!("Unsafe archive path: {name}").into());
        }
        let expected = manifest.files.get(&name).ok_or("Unlisted archive entry")?;
        if file.size() != expected.bytes {
            return Err("Archive size mismatch".into());
        }
        let mut hasher = blake3::Hasher::new();
        let mut bytes = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            bytes += n as u64;
            if bytes > expected.bytes {
                return Err("Archive expanded beyond manifest size".into());
            }
            hasher.update(&buffer[..n]);
        }
        if bytes != expected.bytes || hasher.finalize().to_hex().as_str() != expected.blake3 {
            return Err(format!("Checksum mismatch for {name}").into());
        }
    }
    Ok(manifest)
}

/// Restore never starts a runtime, sync transport, plugin or HTTP client.
/// The marker prevents an accidental normal server boot with copied identities.
pub fn restore(archive: &Path, target: &Path) -> AtomicResult<()> {
    let manifest = verify_archive(archive)?;
    if target.exists() {
        return Err("Restore target must not exist".into());
    }
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let stage = tempfile::Builder::new()
        .prefix(".atomic-restore-")
        .tempdir_in(parent)?;
    let mut zip = zip::ZipArchive::new(File::open(archive)?).map_err(|e| e.to_string())?;
    for name in manifest.files.keys() {
        let dest = stage.path().join(name);
        fs::create_dir_all(dest.parent().unwrap())?;
        let mut file = create_private(&dest)?;
        std::io::copy(
            &mut zip.by_name(name).map_err(|e| e.to_string())?,
            &mut file,
        )?;
        file.sync_all()?;
        let actual = digest(&dest)?;
        let expected = &manifest.files[name];
        if actual.bytes != expected.bytes || actual.blake3 != expected.blake3 {
            return Err("Archive changed during restore".into());
        }
    }
    atomic_lib::db::redb_store::verify_snapshot(&stage.path().join("data/store/atomic.redb"))?;
    fs::write(
        stage.path().join("data").join(RESTORED),
        b"Restored offline. Explicit activation is required before starting a server.\n",
    )?;
    fs::write(
        stage.path().join(MANIFEST),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    // Claim the target without clobbering even an empty directory created by
    // another operation since preflight. Incomplete promotion retains the marker.
    fs::create_dir(target)?;
    private_dir(target)?;
    for item in fs::read_dir(stage.path())? {
        let item = item?;
        fs::rename(item.path(), target.join(item.file_name()))?;
    }
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub fn check_restore_activation(config: &Config) -> AtomicResult<()> {
    if data_dir(config)?.join(RESTORED).exists() && !config.opts.activate_restored {
        return Err("Restored instance is offline. Use --activate-restored only when ready to reconnect its copied identities and integrations".into());
    }
    Ok(())
}

fn create_private(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}
fn private_file(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
fn private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Scheduler-friendly command: wait for this specific job and exit nonzero on
/// failure, replacement or timeout. Never follow redirects with the bearer token.
pub async fn request_backup(server: &str, token_file: &Path) -> AtomicServerResult<()> {
    let url = url::Url::parse(server).map_err(|e| e.to_string())?;
    let loopback = url.host_str().is_some_and(|h| {
        h == "localhost"
            || h.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if !loopback
        || !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("Backup control requires a loopback HTTP(S) URL".into());
    }
    let endpoint = url.join(CONTROL).map_err(|e| e.to_string())?;
    let token = fs::read_to_string(token_file)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let started: Status = client
        .post(endpoint.clone())
        .bearer_auth(token.trim())
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    for _ in 0..7200 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let state: Status = client
            .get(endpoint.clone())
            .bearer_auth(token.trim())
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        if state.id != started.id {
            return Err("Backup status replaced by another job or server restart".into());
        }
        match state.phase.as_str() {
            "complete" => {
                println!("{}", state.archive.ok_or("Missing archive path")?.display());
                return Ok(());
            }
            "failed" => return Err(state.error.unwrap_or_else(|| "Backup failed".into()).into()),
            _ => {}
        }
    }
    Err("Backup wait timed out; inspect status before retrying".into())
}

/// Drain complete requests, including GET class extenders and plugin filesystem
/// operations. The control route must bypass the gate or it would drain itself.
pub async fn admission(
    request: actix_web::dev::ServiceRequest,
    next: actix_web::middleware::Next<impl actix_web::body::MessageBody + 'static>,
) -> Result<actix_web::dev::ServiceResponse<actix_web::body::BoxBody>, actix_web::Error> {
    if request.path() == CONTROL {
        return next.call(request).await.map(|r| r.map_into_boxed_body());
    }
    let gate = request
        .app_data::<web::Data<AppState>>()
        .map(|a| a.store.maintenance.clone());
    if let Some(gate) = gate {
        if gate.is_paused() {
            return Ok(request.into_response(
                HttpResponse::ServiceUnavailable()
                    .insert_header(("Retry-After", "5"))
                    .body("Instance backup capture in progress"),
            ));
        }
        gate.run(next.call(request))
            .await
            .map(|r| r.map_into_boxed_body())
    } else {
        next.call(request).await.map(|r| r.map_into_boxed_body())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atomic_lib::{
        db::{
            kv_store::KvStore,
            redb_store::RedbStore,
            trees::{Method, Operation, Tree},
        },
        loro::AtomicLoroDoc,
        Value,
    };
    use clap::Parser;

    async fn fixture(root: &Path) -> (Db, Config, Arc<BackupService>) {
        let config = crate::config::build_config(crate::config::Opts::parse_from([
            "atomic-server",
            "--data-dir",
            root.join("source").to_str().unwrap(),
            "--config-dir",
            root.join("configuration").to_str().unwrap(),
            "--cache-dir",
            root.join("cache").to_str().unwrap(),
            "--backup-dir",
            root.join("backups").to_str().unwrap(),
        ]))
        .unwrap();
        fs::create_dir_all(&config.config_dir).unwrap();
        let agent = atomic_lib::agents::Agent::new(None).unwrap();
        atomic_lib::config::Config {
            shared: atomic_lib::config::SharedConfig {
                agent_secret: agent.build_secret().unwrap(),
                initial_drive: None,
            },
            client: None,
        }
        .save(&config.config_file_path)
        .unwrap();
        let store = Db::init_redb_file(
            &config.store_path,
            Some("http://localhost:9883".into()),
            &config.uploads_path,
        )
        .await
        .unwrap();
        let service = BackupService::new(&config).unwrap();
        (store, config, service)
    }

    #[tokio::test]
    async fn instance_roundtrip_preserves_history_blobs_metadata_and_files() {
        let root = tempfile::tempdir().unwrap();
        let (store, config, service) = fixture(root.path()).await;
        let doc = AtomicLoroDoc::new();
        doc.set_property("name", &Value::String("before".into()))
            .unwrap();
        let first = doc.export_snapshot();
        let first_version = doc.current_version();
        doc.set_property("name", &Value::String("after".into()))
            .unwrap();
        let snapshot = doc.export_snapshot();
        assert_ne!(first, snapshot);
        store
            .kv
            .insert(Tree::LoroSnapshots, b"did:ad:test", &snapshot)
            .unwrap();
        for tree in [
            Tree::Blobs,
            Tree::Envelopes,
            Tree::PluginMeta,
            Tree::DriveMapping,
        ] {
            store.kv.insert(tree, b"fixture", b"original").unwrap();
        }
        fs::create_dir_all(&config.uploads_path).unwrap();
        fs::write(config.uploads_path.join("legacy.txt"), b"legacy file").unwrap();
        let path = run_backup(&store, &config, &service, "roundtrip")
            .await
            .unwrap();
        assert!(!store.maintenance.is_paused());
        store
            .kv
            .insert(Tree::PluginMeta, b"fixture", b"changed after backup")
            .unwrap();
        let target = root.path().join("restored");
        restore(&path, &target).unwrap();
        assert!(restore(&path, &target).is_err());
        let restored = RedbStore::new_file(&target.join("data/store/atomic.redb")).unwrap();
        assert_eq!(
            restored.get(Tree::PluginMeta, b"fixture").unwrap().unwrap(),
            b"original"
        );
        assert_eq!(
            restored.get(Tree::Blobs, b"fixture").unwrap().unwrap(),
            b"original"
        );
        assert_eq!(
            restored.get(Tree::Envelopes, b"fixture").unwrap().unwrap(),
            b"original"
        );
        let recovered = AtomicLoroDoc::from_snapshot(
            &restored
                .get(Tree::LoroSnapshots, b"did:ad:test")
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(recovered.get_history().len(), doc.get_history().len());
        recovered.fork_at(&first_version).unwrap();
        assert_eq!(
            fs::read(target.join("data/uploads/legacy.txt")).unwrap(),
            b"legacy file"
        );
        assert_eq!(
            fs::read(target.join("config/config.toml")).unwrap(),
            fs::read(&config.config_file_path).unwrap()
        );
        let mut restored_config = config.clone();
        restored_config.store_path = target.join("data/store");
        assert!(check_restore_activation(&restored_config).is_err());
        restored_config.opts.activate_restored = true;
        check_restore_activation(&restored_config).unwrap();
    }

    #[test]
    fn snapshot_blocks_writers_and_copies_unknown_byte_tables() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source.redb");
        // Future tables must not silently disappear from the backup.
        {
            let db = redb_for_test(&source);
            let tx = db.begin_write().unwrap();
            {
                let mut table = tx
                    .open_table(redb::TableDefinition::<&[u8], &[u8]>::new("future_table"))
                    .unwrap();
                table
                    .insert(b"future".as_slice(), b"value".as_slice())
                    .unwrap();
            }
            tx.commit().unwrap();
        }
        let store = Arc::new(RedbStore::new_file(&source).unwrap());
        store
            .apply_batch(&[
                Operation {
                    tree: Tree::Resources,
                    method: Method::Insert,
                    key: b"key".to_vec(),
                    val: Some(b"old".to_vec()),
                },
                Operation {
                    tree: Tree::LoroSnapshots,
                    method: Method::Insert,
                    key: b"key".to_vec(),
                    val: Some(b"old".to_vec()),
                },
            ])
            .unwrap();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let s = store.clone();
        let destination = root.path().join("snapshot.redb");
        let path = destination.clone();
        let backup = std::thread::spawn(move || {
            s.backup_snapshot(&path, &mut || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
        });
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        let s = store.clone();
        let (written_tx, written_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            s.insert(Tree::Resources, b"key", b"new").unwrap();
            written_tx.send(()).unwrap();
        });
        assert!(written_rx
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err());
        release_tx.send(()).unwrap();
        backup.join().unwrap().unwrap();
        writer.join().unwrap();
        let snapshot = RedbStore::new_file(&destination).unwrap();
        assert_eq!(
            snapshot.get(Tree::Resources, b"key").unwrap().unwrap(),
            b"old"
        );
        assert_eq!(
            snapshot.get(Tree::LoroSnapshots, b"key").unwrap().unwrap(),
            b"old"
        );
        drop(snapshot);
        use redb::ReadableDatabase;
        let db = redb_for_test(&destination);
        let tx = db.begin_read().unwrap();
        let table = tx
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new("future_table"))
            .unwrap();
        assert_eq!(
            table.get(b"future".as_slice()).unwrap().unwrap().value(),
            b"value"
        );
    }

    fn redb_for_test(path: &Path) -> redb::Database {
        redb::Database::create(path).unwrap()
    }

    #[tokio::test]
    async fn capture_failure_resumes_and_publishes_nothing() {
        let root = tempfile::tempdir().unwrap();
        let (store, config, service) = fixture(root.path()).await;
        #[cfg(unix)]
        std::os::unix::fs::symlink("/outside", config.config_dir.join("unsupported")).unwrap();
        #[cfg(not(unix))]
        {
            store.kv.begin_batch();
        }
        assert!(run_backup(&store, &config, &service, "failure")
            .await
            .is_err());
        assert!(!store.maintenance.is_paused());
        assert!(!root
            .path()
            .join("backups/atomic-backup-failure.zip")
            .exists());
        store
            .kv
            .insert(Tree::PluginMeta, b"after-failure", b"works")
            .unwrap();
    }

    #[test]
    fn snapshot_callback_failure_releases_storage_barrier() {
        let root = tempfile::tempdir().unwrap();
        let store = RedbStore::new_file(&root.path().join("source.redb")).unwrap();
        assert!(store
            .backup_snapshot(&root.path().join("failed.redb"), &mut || Err(
                "injected I/O failure".into()
            ))
            .is_err());
        store.insert(Tree::PluginMeta, b"after", b"works").unwrap();
        assert!(store
            .backup_snapshot(&root.path().join("failed.redb"), &mut || Ok(()))
            .is_err());
        store.begin_batch();
        assert!(store
            .backup_snapshot(&root.path().join("batch.redb"), &mut || Ok(()))
            .is_err());
        store.commit_batch().unwrap();
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = store.backup_snapshot(&root.path().join("panic.redb"), &mut || {
                panic!("injected capture panic")
            });
        }));
        assert!(panicked.is_err());
        store
            .insert(Tree::PluginMeta, b"after-panic", b"works")
            .unwrap();
    }

    #[tokio::test]
    async fn operator_requires_token_and_loopback_even_during_pause() {
        let root = tempfile::tempdir().unwrap();
        let (store, _config, service) = fixture(root.path()).await;
        use actix_web::test::TestRequest;
        let local = "127.0.0.1:1234".parse().unwrap();
        let request = TestRequest::get().peer_addr(local).to_http_request();
        assert!(!service.authorized(&request));
        let authorized = TestRequest::get()
            .peer_addr(local)
            .insert_header(("Authorization", format!("Bearer {}", service.token)))
            .to_http_request();
        let pause = store.maintenance.pause().await.unwrap();
        assert!(service.authorized(&authorized));
        let remote = TestRequest::get()
            .peer_addr("192.0.2.1:1234".parse().unwrap())
            .insert_header(("Authorization", format!("Bearer {}", service.token)))
            .to_http_request();
        assert!(!service.authorized(&remote));
        drop(pause);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn existing_destination_permissions_are_not_changed() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let (_store, config, _service) = fixture(root.path()).await;
        let output = config.opts.backup_dir.as_ref().unwrap();
        fs::set_permissions(output, fs::Permissions::from_mode(0o755)).unwrap();
        BackupService::new(&config).unwrap();
        assert_eq!(
            fs::metadata(output).unwrap().permissions().mode() & 0o777,
            0o755
        );
        let mut invalid = config.clone();
        invalid.opts.backup_dir = Some(config.config_dir.clone());
        assert!(BackupService::new(&invalid).is_err());
    }

    #[test]
    fn restore_rejects_unsafe_paths() {
        for name in [
            "../escape",
            "data/../../escape",
            "/data/file",
            "config/../escape",
            "data\\escape",
            "data/C:escape",
        ] {
            assert!(!safe_name(name), "{name}");
        }
        assert!(safe_name("data/store/atomic.redb"));
    }
}

#[cfg(test)]
mod sync_tests {
    use super::*;
    use atomic_lib::{
        agents::ForAgent,
        db::trees::Tree,
        loro::AtomicLoroDoc,
        sync::{engine, protocol},
        Storelike, Value,
    };

    #[tokio::test]
    async fn incoming_sync_waits_without_acknowledging_or_losing_the_update() {
        let root = tempfile::tempdir().unwrap();
        let db = Db::init_redb_file(
            &root.path().join("store"),
            Some("http://localhost:9883".into()),
            &root.path().join("uploads"),
        )
        .await
        .unwrap();
        let (agent, drive) = db.setup("Backup sync test").await.unwrap();
        let subject = "did:ad:backup-sync-test";
        let doc = AtomicLoroDoc::new();
        doc.set_property(
            atomic_lib::urls::DRIVE_PROP,
            &Value::AtomicUrl(drive.clone().into()),
        )
        .unwrap();
        doc.set_property(
            atomic_lib::urls::NAME,
            &Value::String("arrived during backup".into()),
        )
        .unwrap();
        let frame = protocol::encode_sync_push(&drive, &[(subject, &doc.export_snapshot())], true);
        let push = protocol::decode_sync_push(&frame[1..]).unwrap();
        let pause = db.maintenance.pause().await.unwrap();
        let receiver = db.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let job = tokio::spawn(async move {
            started_tx.send(()).unwrap();
            engine::import_sync_push(&push, &receiver, &ForAgent::from(agent), false).await
        });
        started_rx.await.unwrap();
        tokio::task::yield_now().await;
        assert!(!job.is_finished(), "must not acknowledge a paused import");
        assert!(db
            .kv
            .get(Tree::LoroSnapshots, subject.as_bytes())
            .unwrap()
            .is_none());
        drop(pause);
        let (count, _) = tokio::time::timeout(std::time::Duration::from_secs(10), job)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            db.get_resource(&subject.into())
                .await
                .unwrap()
                .get(atomic_lib::urls::NAME)
                .unwrap()
                .to_string(),
            "arrived during backup"
        );
    }
}

#[cfg(test)]
mod archive_tests {
    use super::*;

    fn untrusted(root: &Path, name: &str, content: &[u8], expected_hash: &str) -> PathBuf {
        let path = root.join("untrusted.zip");
        let mut files = BTreeMap::new();
        for key in ["data/store/atomic.redb", "config/config.toml", name] {
            files.insert(
                key.into(),
                Entry {
                    bytes: content.len() as u64,
                    blake3: expected_hash.into(),
                },
            );
        }
        let manifest = Manifest {
            format: FORMAT,
            server_version: env!("CARGO_PKG_VERSION").into(),
            build_revision: "test".into(),
            redb_version: "4.1.0".into(),
            snapshot_time: "test".into(),
            freshness: "unknown".into(),
            envelope_retention: "latest".into(),
            source_data: "source".into(),
            source_config: "config".into(),
            files,
        };
        let mut writer = zip::ZipWriter::new(File::create(&path).unwrap());
        let options = zip::write::SimpleFileOptions::default();
        writer.start_file(MANIFEST, options).unwrap();
        writer
            .write_all(&serde_json::to_vec(&manifest).unwrap())
            .unwrap();
        for key in manifest.files.keys() {
            writer.start_file(key, options).unwrap();
            writer.write_all(content).unwrap();
        }
        writer.finish().unwrap();
        path
    }

    #[test]
    fn corrupt_or_traversing_archive_never_creates_restore_target() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("restore");
        let archive = untrusted(root.path(), "data/note", b"tampered", "wrong checksum");
        assert!(restore(&archive, &target)
            .unwrap_err()
            .to_string()
            .contains("Checksum"));
        assert!(!target.exists());
        let hash = blake3::hash(b"valid").to_hex().to_string();
        let archive = untrusted(root.path(), "data/../../escape", b"valid", &hash);
        assert!(restore(&archive, &target)
            .unwrap_err()
            .to_string()
            .contains("Unsafe"));
        assert!(!target.exists());
        assert!(!root.path().join("escape").exists());
    }

    #[test]
    fn valid_hashes_do_not_make_a_corrupt_database_restorable() {
        let root = tempfile::tempdir().unwrap();
        let hash = blake3::hash(b"not a redb file").to_hex().to_string();
        let archive = untrusted(root.path(), "data/note", b"not a redb file", &hash);
        let target = root.path().join("restore");
        assert!(restore(&archive, &target).is_err());
        assert!(!target.exists());
    }
}
