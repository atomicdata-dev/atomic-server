//! The apps loaded on this node, and the small per-installation state the ABI
//! keeps for them (the event queue).
//!
//! Apps are found by reading Installations: a drive's active Installation
//! whose pinned Release is a `sandboxed-app` is compiled once and kept until
//! its release changes or it stops being active. Rights are not cached here;
//! every invocation resolves the Installation again ([`HostCore::for_run`]), so
//! a pause or revocation takes effect on the next call.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{Duration, Instant},
};

use atomic_lib::{agents::ForAgent, storelike::Query, urls, Db, Storelike, Subject, Value};
use wasmtime::{component::Component, Engine};

use super::{
    bindings::SandboxedAppPre,
    run::{instance_pre, AbiState},
};

use crate::plugins::{
    host_core,
    manifest::{Export, Manifest, Runtime, World},
    release,
};

/// How many apps may call each other in one chain before the host refuses.
pub const MAX_CALL_DEPTH: usize = 8;

/// How long a release that failed to load is not tried again. Short enough
/// that a package which was not synced yet is picked up, long enough that a
/// broken one is not recompiled on every call.
const LOAD_FAILURE_TTL: Duration = Duration::from_secs(300);

/// One installed app: a compiled component and what its release declares.
pub struct LoadedApp {
    pub drive: String,
    /// The Installation resource. Its agent is the app's identity.
    pub installation: String,
    /// The pinned release id, when it came from an Installation.
    pub release_id: Option<String>,
    pub manifest: Arc<Manifest>,
    /// The component linked against the host ABI, built once at register.
    pub(super) pre: SandboxedAppPre<AbiState>,
    pub(super) engine: Arc<Engine>,
    /// `drive` as the registry keys it (`Subject::pure_id`).
    drive_key: String,
}

impl LoadedApp {
    pub fn export(&self, interface: &str, function: &str) -> Option<&Export> {
        self.manifest
            .exports
            .iter()
            .find(|e| e.interface == interface && e.function == function)
    }
}

type AppKey = (String, String);

/// Two spellings of one drive or installation (a query or a drive hint on the
/// subject) are one key, as in [`crate::plugins::installation::resolve`].
fn app_key(drive: &str, installation: &str) -> AppKey {
    (
        Subject::from(drive).pure_id(),
        Subject::from(installation).pure_id(),
    )
}

#[derive(Default)]
pub struct HostAbiRegistry {
    apps: RwLock<BTreeMap<AppKey, Arc<LoadedApp>>>,
    /// Releases that failed to load, per installation: (release id, when, why).
    load_failures: Mutex<HashMap<AppKey, (String, Instant, String)>>,
    /// How many times a release was actually read and compiled.
    load_attempts: AtomicUsize,
    /// Where a call goes when no app here can run it (`forward.rs`).
    forwarder: RwLock<Option<Arc<dyn super::forward::CallForwarder>>>,
}

impl HostAbiRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    // -- peers --------------------------------------------------------------

    /// Lets calls this node cannot run go to a peer.
    pub fn set_forwarder(&self, forwarder: Arc<dyn super::forward::CallForwarder>) {
        if let Ok(mut slot) = self.forwarder.write() {
            *slot = Some(forwarder);
        }
    }

    pub(super) fn forwarder(&self) -> Option<Arc<dyn super::forward::CallForwarder>> {
        self.forwarder.read().ok()?.clone()
    }

    // -- apps ---------------------------------------------------------------

    /// Registers a component under an Installation. The manifest must be a
    /// `sandboxed-app`; the Installation is not read here ([`Self::refresh`] and
    /// [`load_installation`] do that) but is resolved on every invocation.
    pub fn register(
        &self,
        drive: &str,
        installation: &str,
        release_id: Option<String>,
        manifest: Manifest,
        wasm: &[u8],
    ) -> Result<Arc<LoadedApp>, String> {
        if manifest.world != World::SandboxedApp || manifest.runtime != Runtime::Wasip2v1 {
            return Err("only a wasip2/1 sandboxed-app runs on the host ABI".into());
        }
        let engine = host_core::engine()?;
        let component = Component::from_binary(&engine, wasm)
            .map_err(|e| format!("the app is not a valid component: {e}"))?;
        let pre = instance_pre(&engine, &component)?;
        let key = app_key(drive, installation);
        let app = Arc::new(LoadedApp {
            drive_key: key.0.clone(),
            drive: drive.to_string(),
            installation: installation.to_string(),
            release_id,
            manifest: Arc::new(manifest),
            pre,
            engine,
        });
        self.apps
            .write()
            .map_err(|_| "registry lock poisoned")?
            .insert(key, app.clone());
        Ok(app)
    }

    pub fn unregister(&self, drive: &str, installation: &str) {
        let key = app_key(drive, installation);
        if let Ok(mut apps) = self.apps.write() {
            apps.remove(&key);
        }
        if let Ok(mut failures) = self.load_failures.lock() {
            failures.remove(&key);
        }
    }

    pub fn app(&self, drive: &str, installation: &str) -> Option<Arc<LoadedApp>> {
        self.apps
            .read()
            .ok()?
            .get(&app_key(drive, installation))
            .cloned()
    }

    /// Every app in `drive` that declares `interface`, preferred first.
    ///
    /// "Preferred" is the installation subject in sorted order for now: stable
    /// and the same on every node. A user-chosen default provider is a
    /// resource on the drive later.
    pub fn providers(&self, drive: &str, interface: &str) -> Vec<Arc<LoadedApp>> {
        let drive = Subject::from(drive).pure_id();
        let Ok(apps) = self.apps.read() else {
            return Vec::new();
        };
        apps.values()
            .filter(|app| {
                app.drive_key == drive && app.manifest.exports_of(interface).next().is_some()
            })
            .cloned()
            .collect()
    }

    /// The provider of `interface.function` in `drive`.
    pub fn provider_of(
        &self,
        drive: &str,
        interface: &str,
        function: &str,
    ) -> Option<Arc<LoadedApp>> {
        self.providers(drive, interface)
            .into_iter()
            .find(|app| app.export(interface, function).is_some())
    }

    /// Loads the drive's `sandboxed-app` Installations that are not loaded yet
    /// (or whose pinned release changed), and drops apps whose Installation is
    /// gone, paused or revoked. Returns how many apps are loaded for the drive.
    ///
    /// Discovery reads the drive as the server, because it is the server
    /// deciding which code to compile; nothing it reads reaches an app, and
    /// every release is checked against the id its Installation pinned.
    pub async fn refresh(&self, db: &Db, drive: &str) -> usize {
        let mut query = Query::new_class(urls::INSTALLATION);
        query.drive = Some(drive.into());
        query.for_agent = ForAgent::Sudo;
        query.include_nested = false;
        let found = match db.query(&query).await {
            Ok(result) => result.subjects,
            Err(e) => {
                tracing::warn!("host ABI: cannot list installations of {drive}: {e}");
                return self.providers_in(drive).len();
            }
        };

        let mut live = Vec::new();
        for subject in found {
            let subject = subject.to_string();
            match load_installation(self, db, drive, &subject).await {
                Ok(true) => live.push(subject),
                Ok(false) => {}
                Err(e) => tracing::warn!("host ABI: not loading {subject}: {e}"),
            }
        }
        let stale: Vec<String> = self
            .providers_in(drive)
            .into_iter()
            .map(|app| app.installation.clone())
            .filter(|installation| !live.contains(installation))
            // An app registered by hand (tests, an operator) has no
            // Installation resource to refresh from.
            .filter(|installation| db.has_resource_locally(installation))
            .collect();
        for installation in stale {
            self.unregister(drive, &installation);
        }
        self.providers_in(drive).len()
    }

    /// Every app loaded for `drive`, in installation order.
    pub fn providers_in(&self, drive: &str) -> Vec<Arc<LoadedApp>> {
        let drive = Subject::from(drive).pure_id();
        self.apps
            .read()
            .map(|apps| {
                apps.values()
                    .filter(|app| app.drive_key == drive)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Why this release of this installation could not be loaded, if that was
    /// found out recently.
    fn load_failure(&self, drive: &str, installation: &str, release_id: &str) -> Option<String> {
        let failures = self.load_failures.lock().ok()?;
        let (id, at, why) = failures.get(&app_key(drive, installation))?;
        (id == release_id && at.elapsed() < LOAD_FAILURE_TTL).then(|| why.clone())
    }

    fn note_load_failure(&self, drive: &str, installation: &str, release_id: &str, why: &str) {
        if let Ok(mut failures) = self.load_failures.lock() {
            failures.insert(
                app_key(drive, installation),
                (release_id.to_string(), Instant::now(), why.to_string()),
            );
        }
    }

    /// How many times a release was read and compiled (not served from the
    /// failure cache).
    pub fn load_attempts(&self) -> usize {
        self.load_attempts.load(Ordering::SeqCst)
    }
}

/// Reads one Installation and registers its app. `Ok(false)` when the
/// resource is not an active host-ABI Installation (other runtimes are none of
/// this module's business); `Err` when it is one but cannot be loaded.
pub async fn load_installation(
    registry: &HostAbiRegistry,
    db: &Db,
    drive: &str,
    installation: &str,
) -> Result<bool, String> {
    let resource = db
        .get_resource(&installation.into())
        .await
        .map_err(|e| e.to_string())?;
    if !resource.has_class(urls::INSTALLATION)
        || crate::plugins::installation::is_suspended(&resource)
    {
        return Ok(false);
    }
    let string = |prop: &str| {
        resource.get(prop).ok().map(|value| match value {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
    };
    let reference = string(urls::RELEASE_PROP).ok_or("an Installation needs a release")?;
    let pinned = string(urls::RELEASE_ID).ok_or("an Installation needs a releaseId")?;

    if let Some(app) = registry.app(drive, installation) {
        if app.release_id.as_deref() == Some(pinned.as_str()) {
            return Ok(true);
        }
    }

    if let Some(why) = registry.load_failure(drive, installation, &pinned) {
        return Err(format!("{why} (not retried yet)"));
    }
    registry.load_attempts.fetch_add(1, Ordering::SeqCst);
    match load_release(
        registry,
        db,
        drive,
        installation,
        &resource,
        &reference,
        &pinned,
    )
    .await
    {
        Ok(loaded) => Ok(loaded),
        Err(why) => {
            registry.note_load_failure(drive, installation, &pinned, &why);
            Err(why)
        }
    }
}

async fn load_release(
    registry: &HostAbiRegistry,
    db: &Db,
    drive: &str,
    installation: &str,
    resource: &atomic_lib::Resource,
    reference: &str,
    pinned: &str,
) -> Result<bool, String> {
    // Hash-verified against the pin below, and never shown to an app.
    let plugin_release = release::resolve(db, reference, &ForAgent::Sudo)
        .await
        .map_err(|e| e.to_string())?;
    if plugin_release.is_js()
        || plugin_release.world != atomic_lib::db::plugin_release::WORLD_SANDBOXED_APP
    {
        return Ok(false);
    }
    let actual = plugin_release.id().map_err(|e| e.to_string())?;
    if actual != pinned {
        return Err(format!(
            "the Installation pins release {pinned} but its release resolves to {actual}"
        ));
    }
    let manifest = Manifest::parse(plugin_release.manifest.clone())?
        .ok_or("the release has no versioned manifest")?;

    // The grants the Installation holds must be what the release declares.
    let grants = match resource.get(urls::GRANTS) {
        Ok(Value::Json(json)) => json.clone(),
        Ok(Value::String(s)) => serde_json::from_str(s).map_err(|e| e.to_string())?,
        _ => serde_json::Value::Null,
    };
    release::check_grants(&plugin_release.manifest, &grants).map_err(|e| e.to_string())?;

    let package = plugin_release
        .package
        .as_deref()
        .ok_or("a wasip2 release without a package")?;
    let bytes = release::package_bytes(db, package)
        .await
        .map_err(|e| e.to_string())?;
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| format!("package is not a zip archive: {e}"))?;
    let wasm = crate::plugins::wasm::wasm_bytes_from_zip(&mut zip).map_err(|e| e.to_string())?;

    registry.register(
        drive,
        installation,
        Some(pinned.to_string()),
        manifest,
        &wasm,
    )?;
    Ok(true)
}
