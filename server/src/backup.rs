//! Native instance backup. Control is opt-in, loopback-only and token-protected.
//! Capture owns the maintenance guard in the blocking worker, so cancellation
//! of an HTTP request cannot resume writers while files are still being copied.
use crate::{appstate::AppState, config::Config, errors::AtomicServerResult};
use actix_web::{web, HttpRequest, HttpResponse};
pub use atomic_lib::backup::restore;
use atomic_lib::{
    backup::{CheckpointOptions, Phase},
    errors::AtomicResult,
    Db,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

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
            checkpoint_options(config, path.clone())?.prepare()?;
            let output = path.canonicalize()?;
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

fn checkpoint_options(config: &Config, output_dir: PathBuf) -> AtomicResult<CheckpointOptions> {
    Ok(CheckpointOptions {
        data_dir: data_dir(config)?,
        config_dir: config.config_dir.clone(),
        output_dir,
        build_revision: env!("ATOMIC_BACKUP_REVISION").into(),
    })
}

async fn run_backup(
    store: &Db,
    config: &Config,
    service: &Arc<BackupService>,
    id: &str,
) -> AtomicResult<PathBuf> {
    let options = checkpoint_options(config, service.output.clone().ok_or("Backups disabled")?)?;
    let service = service.clone();
    atomic_lib::backup::create(store, &options, id, move |phase| {
        service.phase(match phase {
            Phase::Capturing => "capturing",
            Phase::Archiving => "archiving",
        });
    })
    .await
}

pub fn check_restore_activation(config: &Config) -> AtomicResult<()> {
    atomic_lib::backup::check_restore_activation(&data_dir(config)?, config.opts.activate_restored)
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
}
