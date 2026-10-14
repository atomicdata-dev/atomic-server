//! The apps loaded on this node, and the small per-installation state the ABI
//! keeps for them (event queue, subscriptions, proposals).
//!
//! Apps are found by reading Installations: a drive's active Installation
//! whose pinned Release is a `sandboxed-app` is compiled once and kept until
//! its release changes or it stops being active. Rights are not cached here;
//! every invocation resolves the Installation again ([`HostCore::for_run`]), so
//! a pause or revocation takes effect on the next call.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{Arc, Mutex, RwLock},
};

use atomic_lib::{agents::ForAgent, storelike::Query, urls, Db, Storelike, Value};
use wasmtime::{component::Component, Engine};

use super::bindings::atomic::host::{events::Event, events::Kind, store::QuerySpec};
use crate::plugins::{
    host_core,
    manifest::{Export, Manifest, Runtime, World},
    release,
};

/// How many apps may call each other in one chain before the host refuses.
pub const MAX_CALL_DEPTH: usize = 8;

/// Events kept per installation. The oldest are dropped past this; a stream
/// that nobody reads must not grow without bound.
const EVENT_QUEUE_CAP: usize = 1000;
/// Subscriptions one installation may hold.
pub(super) const SUBSCRIPTION_CAP: usize = 64;
/// Proposals kept in memory per installation.
const PROPOSAL_CAP: usize = 100;

/// One installed app: a compiled component and what its release declares.
pub struct LoadedApp {
    pub drive: String,
    /// The Installation resource. Its agent is the app's identity.
    pub installation: String,
    /// The pinned release id, when it came from an Installation.
    pub release_id: Option<String>,
    pub manifest: Manifest,
    pub(super) component: Component,
    pub(super) engine: Arc<Engine>,
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

/// A write the app asked for that the host did not apply, kept for review.
///
/// In memory only: a restart forgets it. Durable proposals belong to the
/// event/proposal work in step 3 of `planning/host-abi.md`.
#[derive(Clone, Debug)]
pub struct Proposal {
    pub drive: String,
    pub installation: String,
    pub caller: String,
    pub at_ms: i64,
    /// The intents as the planner understands them (`{"intents": [...]}`).
    pub verdict: serde_json::Value,
}

#[derive(Default)]
struct EventQueue {
    next: u64,
    /// The last cursor the app acknowledged.
    checkpoint: u64,
    pending: VecDeque<(u64, Event)>,
}

#[derive(Default)]
pub struct HostAbiRegistry {
    apps: RwLock<BTreeMap<AppKey, Arc<LoadedApp>>>,
    events: Mutex<HashMap<AppKey, EventQueue>>,
    subscriptions: Mutex<HashMap<AppKey, BTreeMap<String, QuerySpec>>>,
    proposals: Mutex<HashMap<AppKey, VecDeque<Proposal>>>,
}

impl HostAbiRegistry {
    pub fn new() -> Self {
        Self::default()
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
        let app = Arc::new(LoadedApp {
            drive: drive.to_string(),
            installation: installation.to_string(),
            release_id,
            manifest,
            component,
            engine,
        });
        self.apps
            .write()
            .map_err(|_| "registry lock poisoned")?
            .insert((drive.to_string(), installation.to_string()), app.clone());
        Ok(app)
    }

    pub fn unregister(&self, drive: &str, installation: &str) {
        let key = (drive.to_string(), installation.to_string());
        if let Ok(mut apps) = self.apps.write() {
            apps.remove(&key);
        }
        if let Ok(mut events) = self.events.lock() {
            events.remove(&key);
        }
        if let Ok(mut subs) = self.subscriptions.lock() {
            subs.remove(&key);
        }
        if let Ok(mut proposals) = self.proposals.lock() {
            proposals.remove(&key);
        }
    }

    pub fn app(&self, drive: &str, installation: &str) -> Option<Arc<LoadedApp>> {
        self.apps
            .read()
            .ok()?
            .get(&(drive.to_string(), installation.to_string()))
            .cloned()
    }

    /// Every app in `drive` that declares `interface`, preferred first.
    ///
    /// "Preferred" is the installation subject in sorted order for now: stable
    /// and the same on every node. A user-chosen default provider is a
    /// resource on the drive later.
    pub fn providers(&self, drive: &str, interface: &str) -> Vec<Arc<LoadedApp>> {
        let Ok(apps) = self.apps.read() else {
            return Vec::new();
        };
        apps.values()
            .filter(|app| app.drive == drive && app.manifest.exports_of(interface).next().is_some())
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

    fn providers_in(&self, drive: &str) -> Vec<Arc<LoadedApp>> {
        self.apps
            .read()
            .map(|apps| {
                apps.values()
                    .filter(|app| app.drive == drive)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    // -- events -------------------------------------------------------------

    /// Queues an event for an installation. The only producer in this slice;
    /// the trigger edges (`triggers.rs`) are not wired to it yet.
    pub fn push_event(&self, drive: &str, installation: &str, kind: Kind, subject: Option<String>) {
        let Ok(mut queues) = self.events.lock() else {
            return;
        };
        let queue = queues
            .entry((drive.to_string(), installation.to_string()))
            .or_default();
        queue.next += 1;
        let cursor = queue.next;
        queue.pending.push_back((
            cursor,
            Event {
                cursor: cursor.to_string(),
                kind,
                subject,
                at_ms: atomic_lib::utils::now().max(0) as u64,
            },
        ));
        while queue.pending.len() > EVENT_QUEUE_CAP {
            queue.pending.pop_front();
        }
    }

    pub(super) fn next_events(
        &self,
        drive: &str,
        installation: &str,
        after: Option<u64>,
        max: usize,
    ) -> Vec<Event> {
        let Ok(queues) = self.events.lock() else {
            return Vec::new();
        };
        let Some(queue) = queues.get(&(drive.to_string(), installation.to_string())) else {
            return Vec::new();
        };
        let after = after.unwrap_or(queue.checkpoint);
        queue
            .pending
            .iter()
            .filter(|(cursor, _)| *cursor > after)
            .take(max)
            .map(|(_, event)| event.clone())
            .collect()
    }

    pub(super) fn ack_events(&self, drive: &str, installation: &str, up_to: u64) {
        let Ok(mut queues) = self.events.lock() else {
            return;
        };
        let queue = queues
            .entry((drive.to_string(), installation.to_string()))
            .or_default();
        queue.checkpoint = queue.checkpoint.max(up_to);
        let checkpoint = queue.checkpoint;
        queue.pending.retain(|(cursor, _)| *cursor > checkpoint);
    }

    // -- subscriptions ------------------------------------------------------

    pub(super) fn subscribe(
        &self,
        drive: &str,
        installation: &str,
        spec: QuerySpec,
    ) -> Result<String, String> {
        let mut subs = self.subscriptions.lock().map_err(|_| "lock poisoned")?;
        let held = subs
            .entry((drive.to_string(), installation.to_string()))
            .or_default();
        if held.len() >= SUBSCRIPTION_CAP {
            return Err(format!(
                "at most {SUBSCRIPTION_CAP} subscriptions per installation"
            ));
        }
        let id = format!("sub:{}", ulid::Ulid::new().to_string().to_lowercase());
        held.insert(id.clone(), spec);
        Ok(id)
    }

    pub(super) fn unsubscribe(&self, drive: &str, installation: &str, id: &str) {
        if let Ok(mut subs) = self.subscriptions.lock() {
            if let Some(held) = subs.get_mut(&(drive.to_string(), installation.to_string())) {
                held.remove(id);
            }
        }
    }

    /// The queries an installation subscribed to, by subscription id.
    pub fn subscriptions(&self, drive: &str, installation: &str) -> Vec<(String, QuerySpec)> {
        self.subscriptions
            .lock()
            .ok()
            .and_then(|subs| {
                subs.get(&(drive.to_string(), installation.to_string()))
                    .map(|held| held.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            })
            .unwrap_or_default()
    }

    // -- proposals ----------------------------------------------------------

    pub(super) fn keep_proposal(&self, proposal: Proposal) {
        let Ok(mut all) = self.proposals.lock() else {
            return;
        };
        let held = all
            .entry((proposal.drive.clone(), proposal.installation.clone()))
            .or_default();
        held.push_back(proposal);
        while held.len() > PROPOSAL_CAP {
            held.pop_front();
        }
    }

    pub fn proposals(&self, drive: &str, installation: &str) -> Vec<Proposal> {
        self.proposals
            .lock()
            .ok()
            .and_then(|all| {
                all.get(&(drive.to_string(), installation.to_string()))
                    .map(|held| held.iter().cloned().collect())
            })
            .unwrap_or_default()
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

    // Hash-verified against the pin below, and never shown to an app.
    let plugin_release = release::resolve(db, &reference, &ForAgent::Sudo)
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

    registry.register(drive, installation, Some(pinned), manifest, &wasm)?;
    Ok(true)
}
