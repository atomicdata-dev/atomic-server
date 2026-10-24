//! Server modules (class extenders) on this node: loading them, and the
//! package checks that decide what a zip is. The component itself runs in
//! [`super::host_abi::ServerModule`].
//!
//! An Installation's module is loaded from its pinned Release's package, in
//! memory, the way sandboxed apps are ([`super::host_abi::HostAbiRegistry`]).
//! Nothing of the package is kept on disk except what the module itself reads
//! through WASI: its `storage` folder, which `assets/` of the package is
//! written into. The operator's `class-extenders/global/` folder is the other
//! source of modules.

use std::{
    collections::HashSet,
    ffi::OsStr,
    io::Cursor,
    path::{Path, PathBuf},
    sync::Arc,
};

use atomic_lib::{
    agents::{Agent, ForAgent},
    class_extender::ClassExtenderScope,
    db::app_agent::{AppAgent, AppAgentKey, AppAgentState},
    db::plugin_meta::PluginMetaKey,
    db::plugin_meta::{validate_plugin_identifiers, PermissionType, PluginManifest, PluginMeta},
    db::plugin_release::{PluginRelease, WORLD_SANDBOXED_APP},
    errors::{AtomicError, AtomicResult},
    storelike::Query,
    urls, Db, Storelike, Value,
};
use base64::{engine::general_purpose, Engine as _};
use tracing::{error, info, warn};
use wasmtime::{component::Component, Engine};
use zip::ZipArchive;

use super::host_abi::{HostAbiRegistry, ModuleParts, ServerModule};
use super::host_core;
use super::manifest::Manifest;
use super::release;

const CLASS_EXTENDER_DIR_NAME: &str = "class-extenders"; // Relative to the store path.

/// Loads every module this node runs at boot: the operator's `global/` folder
/// and the active Installations of a server module, each from its pinned
/// release. All of them are registered on `db`.
pub async fn load_wasm_class_extenders(
    plugin_path: &Path,
    plugin_cache_path: &Path,
    db: &Db,
    registry: &Arc<HostAbiRegistry>,
) -> AtomicResult<()> {
    let global_dir = plugin_path.join(CLASS_EXTENDER_DIR_NAME).join("global");
    if let Err(err) = std::fs::create_dir_all(&global_dir) {
        warn!(error = %err, path = %global_dir.display(), "Failed to create Wasm extender directory");
    }
    let engine = match host_core::engine() {
        Ok(engine) => engine,
        Err(err) => {
            error!(error = %err, "Failed to initialize Wasm engine. Skipping dynamic class extenders");
            return Ok(());
        }
    };

    info!("Loading plugins...");
    let mut used_cwasm_files = HashSet::new();

    for path in find_wasm_files(&global_dir) {
        match load_global_module(&path, &global_dir, plugin_cache_path, &engine, db, registry).await
        {
            Ok(cwasm) => {
                used_cwasm_files.insert(cwasm);
            }
            Err(err) => {
                error!(error = %err, path = %path.display(), "Failed to load Wasm class extender")
            }
        }
    }

    used_cwasm_files
        .extend(load_installed_modules(db, plugin_path, plugin_cache_path, registry).await);
    prune_cache(plugin_cache_path, &used_cwasm_files);
    Ok(())
}

async fn load_global_module(
    path: &Path,
    global_dir: &Path,
    cache_dir: &Path,
    engine: &Arc<Engine>,
    db: &Db,
    registry: &Arc<HostAbiRegistry>,
) -> AtomicResult<PathBuf> {
    let wasm_bytes = std::fs::read(path)
        .map_err(|e| AtomicError::from(format!("Failed to read Wasm file: {e}")))?;
    let (component, cwasm) = load_component(engine, &wasm_bytes, cache_dir)?;
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_string();
    let parts = ModuleParts {
        file_name: file_name.clone(),
        scope: ClassExtenderScope::Global,
        installation: None,
        agent: None,
        data_dir: setup_plugin_data_dir(path, global_dir),
        manifest: None,
        registry: registry.clone(),
    };
    let module = ServerModule::new(engine.clone(), component, db, parts).await?;
    db.add_class_extender(module.into_class_extender())?;
    info!("Loaded {file_name}");
    Ok(cwasm)
}

/// Loads the active Installations of a server module from the releases they
/// pin, which activation cached by id. A paused installation keeps its
/// identity and is not loaded; resuming it activates it again. Returns the
/// compiled-component files in use.
async fn load_installed_modules(
    db: &Db,
    plugins_dir: &Path,
    cache_dir: &Path,
    registry: &Arc<HostAbiRegistry>,
) -> Vec<PathBuf> {
    let mut query = Query::new_class(urls::INSTALLATION);
    query.for_agent = ForAgent::Sudo;
    query.include_nested = false;
    let found = match db.query(&query).await {
        Ok(result) => result.subjects,
        Err(e) => {
            warn!("cannot list installations to load: {e}");
            return Vec::new();
        }
    };
    let mut used = Vec::new();
    for subject in found {
        let subject = subject.to_string();
        let loaded = async {
            let resource = db.get_resource(&subject.as_str().into()).await?;
            if super::installation::is_suspended(&resource) {
                return Ok(None);
            }
            let pinned = match resource.get(urls::RELEASE_ID) {
                Ok(Value::String(id)) => id.clone(),
                _ => return Ok(None),
            };
            let release = db.get_plugin_release(&pinned)?;
            if !is_server_module(&release) {
                return Ok(None);
            }
            let drive = super::plugin::get_parent_drive(&resource, db).await?;
            activate_module(
                db,
                &drive,
                &subject,
                &pinned,
                &release,
                plugins_dir,
                cache_dir,
                registry,
            )
            .await
            .map(Some)
        }
        .await;
        match loaded {
            Ok(Some(cwasm)) => used.push(cwasm),
            Ok(None) => {}
            Err(e) => error!("Failed to load the module of installation {subject}: {e}"),
        }
    }
    used
}

/// Whether a release is a class extender that runs on this node, as opposed
/// to a sandboxed app or a JS runtime.
pub fn is_server_module(release: &PluginRelease) -> bool {
    release.is_wasip2() && release.world != WORLD_SANDBOXED_APP
}

/// The registry id of an Installation's class extender.
pub fn extender_id(drive_subject: &str, installation: &str) -> String {
    format!("{drive_subject}:{installation}")
}

pub fn validate_plugin_zip(
    zip: &mut ZipArchive<std::io::Cursor<Vec<u8>>>,
) -> AtomicResult<PluginManifest> {
    // Check for plugin.wasm
    if zip.by_name("plugin.wasm").is_err() {
        return Err(AtomicError::from("Missing plugin.wasm"));
    }

    // Check for plugin.json and read it
    let file = zip
        .by_name("plugin.json")
        .map_err(|_| AtomicError::from("Missing plugin.json"))?;

    let manifest = PluginManifest::from_reader(file)?;

    let mut has_ui_js = false;

    for i in 0..zip.len() {
        let file = zip
            .by_index(i)
            .map_err(|e| AtomicError::from(e.to_string()))?;
        let name = file.name();
        if name == "plugin.wasm"
            || name == "plugin.json"
            || name == "ui.js"
            || name == "ui.css"
            || name.starts_with("assets/")
        {
            if name == "ui.js" {
                has_ui_js = true;
            }
            continue;
        }
        // If it's a directory "assets/", that's fine too.
        if name == "assets/" {
            continue;
        }
        return Err(AtomicError::from(format!(
            "Illegal file found in zip: {}. Only plugin.wasm, plugin.json, ui.js, ui.css and assets/ are allowed.",
            name
        )));
    }

    if has_ui_js && !manifest.has_permission(PermissionType::CustomView) {
        return Err(AtomicError::from(
            "Plugin contains ui.js but does not have the 'custom-view' permission.",
        ));
    }

    Ok(manifest)
}

/// The `plugin.wasm` inside a validated package.
pub fn wasm_bytes_from_zip(
    zip: &mut ZipArchive<std::io::Cursor<Vec<u8>>>,
) -> AtomicResult<Vec<u8>> {
    let mut file = zip
        .by_name("plugin.wasm")
        .map_err(|_| AtomicError::from("Missing plugin.wasm"))?;
    let mut bytes = Vec::with_capacity(file.size() as usize);
    std::io::Read::read_to_end(&mut file, &mut bytes)
        .map_err(|e| AtomicError::from(format!("Could not read plugin.wasm: {e}")))?;
    Ok(bytes)
}

/// Asks a component which classes it extends, by loading it once as a global
/// module (the public agent, no folder, no manifest) and calling `classes`.
/// `plugin.json` alone does not say; this is what decides the package's world.
pub async fn read_class_urls(db: &Db, wasm_bytes: &[u8]) -> AtomicResult<Vec<String>> {
    let engine = host_core::engine().map_err(AtomicError::from)?;
    let component = Component::from_binary(&engine, wasm_bytes)
        .map_err(|e| AtomicError::from(format!("the package is not a server module: {e}")))?;
    let parts = ModuleParts {
        file_name: "plugin.wasm".into(),
        scope: ClassExtenderScope::Global,
        installation: None,
        agent: None,
        data_dir: None,
        manifest: None,
        // Only asked which classes it extends: it calls nobody.
        registry: Arc::default(),
    };
    Ok(ServerModule::new(engine, component, db, parts)
        .await?
        .classes()
        .to_vec())
}

/// Validates a package and translates its `plugin.json` into the version-two
/// manifest, with `world` and `entrypoints.classExtender` taken from the
/// component itself. This is the manifest a wasip2 Release carries.
pub async fn describe_package(
    db: &Db,
    zip: &mut ZipArchive<std::io::Cursor<Vec<u8>>>,
) -> AtomicResult<Manifest> {
    let plugin_json = validate_plugin_zip(zip)?;
    let wasm_bytes = wasm_bytes_from_zip(zip)?;
    let class_urls = read_class_urls(db, &wasm_bytes).await?;
    translate_plugin_json(&plugin_json, &class_urls)
}

fn translate_plugin_json(
    plugin_json: &PluginManifest,
    class_urls: &[String],
) -> AtomicResult<Manifest> {
    super::manifest::translate_plugin_json(plugin_json, class_urls)
        .map_err(|e| AtomicError::from(format!("plugin.json does not translate: {e}")))
}

/// The namespace and name a wasip2 manifest carries; translation always sets
/// them, so a manifest without them did not come from a package.
fn manifest_identifiers(manifest: &Manifest) -> AtomicResult<(&str, &str)> {
    let namespace = manifest
        .namespace
        .as_deref()
        .ok_or("a wasip2 manifest needs a namespace")?;
    let name = manifest
        .name
        .as_deref()
        .ok_or("a wasip2 manifest needs a name")?;
    validate_plugin_identifiers(namespace, name)?;
    Ok((namespace, name))
}

/// Loads an Installation's module from the bytes of its release and registers
/// it, replacing the previous one. Records the plugin's identity and the
/// release's manifest in `PluginMeta`; when loading fails that record goes
/// back to what it was. Returns the compiled-component file in use.
#[allow(clippy::too_many_arguments)]
pub async fn activate_module(
    db: &Db,
    drive_subject: &str,
    installation: &str,
    release_id: &str,
    release: &PluginRelease,
    plugins_dir: &Path,
    cache_dir: &Path,
    registry: &Arc<HostAbiRegistry>,
) -> AtomicResult<PathBuf> {
    let package = release
        .package
        .as_deref()
        .ok_or("a wasip2 release without a package")?;
    let bytes = release::package_bytes(db, package).await?;
    let mut zip = ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| AtomicError::from(format!("package is not a zip archive: {e}")))?;
    validate_plugin_zip(&mut zip)?;
    let wasm_bytes = wasm_bytes_from_zip(&mut zip)?;
    // A release published before manifests were unified carries its
    // `plugin.json`; the package itself says what it translates to.
    let manifest = match Manifest::parse(release.manifest.clone()) {
        Ok(Some(manifest)) => manifest,
        Ok(None) => describe_package(db, &mut zip).await?,
        Err(e) => {
            return Err(AtomicError::from(format!(
                "release manifest is invalid: {e}"
            )))
        }
    };
    let (namespace, name) = manifest_identifiers(&manifest)?;
    let key = PluginMetaKey::new(drive_subject, namespace, name);
    let previous = db.get_plugin_meta(&key)?;

    let loaded = async {
        let agent = create_plugin_meta(
            db,
            &key,
            &manifest,
            installation,
            release_id,
            previous.as_ref(),
        )
        .await?;
        bind_installation_agent(db, drive_subject, installation, &agent)?;
        let data_dir = scoped_data_dir(plugins_dir, drive_subject, namespace)?;
        extract_assets(&mut zip, &data_dir)?;
        let engine = host_core::engine().map_err(AtomicError::from)?;
        let (component, cwasm) = load_component(&engine, &wasm_bytes, cache_dir)?;
        let parts = ModuleParts {
            file_name: installation.to_string(),
            scope: ClassExtenderScope::Drive(drive_subject.to_string()),
            installation: Some(installation.to_string()),
            agent: Some(agent),
            data_dir: Some(data_dir),
            manifest: Some(manifest.clone()),
            registry: registry.clone(),
        };
        let module = ServerModule::new(engine, component, db, parts).await?;
        db.add_class_extender(module.into_class_extender())?;
        Ok(cwasm)
    }
    .await;

    if let Err(e) = &loaded {
        warn!("Loading {namespace}.{name} failed, keeping what was there: {e}");
        match previous {
            Some(old) => {
                if let Err(e) = db.set_plugin_meta(&key, &old) {
                    error!("Rollback: failed to restore plugin metadata: {e}");
                }
            }
            None => {
                if let Err(e) = delete_plugin_meta(db, drive_subject, namespace, name).await {
                    error!("Rollback: failed to delete plugin metadata: {e}");
                }
            }
        }
    }
    loaded
}

/// The folder a drive-scoped module reads and (with `storage`) writes through
/// WASI. Shared by the plugins of one namespace on a drive.
fn scoped_data_dir(
    plugins_dir: &Path,
    drive_subject: &str,
    namespace: &str,
) -> AtomicResult<PathBuf> {
    let dir = plugins_dir
        .join(CLASS_EXTENDER_DIR_NAME)
        .join("scoped")
        .join(general_purpose::URL_SAFE.encode(drive_subject))
        .join(namespace);
    std::fs::create_dir_all(&dir)
        .map_err(|e| AtomicError::from(format!("Failed to create {}: {e}", dir.display())))?;
    Ok(dir)
}

/// Writes the package's `assets/` into the module's folder, where it reads them.
fn extract_assets(zip: &mut ZipArchive<Cursor<Vec<u8>>>, data_dir: &Path) -> AtomicResult<()> {
    for i in 0..zip.len() {
        let mut file = zip
            .by_index(i)
            .map_err(|e| AtomicError::from(e.to_string()))?;
        let name = file.name().to_string();
        let Some(stripped) = name.strip_prefix("assets/").filter(|s| !s.is_empty()) else {
            continue;
        };
        // Zip entry names are attacker-controlled: only plain relative paths.
        let target = data_dir.join(
            safe_relative_path(stripped.trim_end_matches('/')).ok_or_else(|| {
                AtomicError::from(format!("Plugin zip contains an unsafe asset path: {name}"))
            })?,
        );
        let written = if file.is_dir() {
            std::fs::create_dir_all(&target)
        } else {
            target
                .parent()
                .map_or(Ok(()), std::fs::create_dir_all)
                .and_then(|()| std::fs::File::create(&target))
                .and_then(|mut out| std::io::copy(&mut file, &mut out).map(drop))
        };
        written
            .map_err(|e| AtomicError::from(format!("Failed to write {}: {e}", target.display())))?;
    }
    Ok(())
}

fn find_wasm_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension() == Some(OsStr::new("wasm")) {
                files.push(path);
            }
        }
    }
    files
}

fn setup_plugin_data_dir(wasm_file_path: &Path, plugin_dir: &Path) -> Option<PathBuf> {
    let filename = wasm_file_path.file_name().and_then(|s| s.to_str())?;

    // Remove .wasm extension
    let stem = wasm_file_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(filename);

    let stem_path = Path::new(stem);

    // If there is no second extension (e.g. just my-plugin.wasm), we don't grant access to a folder.
    // This is to prevent plugins from accessing arbitrary folders.
    // Only namespaced plugins (e.g. google.calendar.wasm or my-plugin.plugin.wasm) get a folder.
    stem_path.extension()?;

    // Remove the second extension (e.g. .plugin in my_script.plugin.wasm), if present.
    // This allows for any suffix without dots.
    let plugin_name = stem_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(stem);

    let data_dir = plugin_dir.join(plugin_name);

    if !data_dir.exists() {
        if let Err(err) = std::fs::create_dir_all(&data_dir) {
            warn!(
                error = %err,
                path = %data_dir.display(),
                "Failed to create data directory for plugin"
            );
            return None;
        }
    }

    if data_dir.exists() {
        Some(data_dir)
    } else {
        None
    }
}

/// Returns `Some(path)` if `raw` is a relative path consisting only of normal components
/// (no `..`, no root/prefix, no `.`), otherwise `None`.
fn safe_relative_path(raw: &str) -> Option<PathBuf> {
    use std::path::Component;

    // Zip archives always use `/`, but be strict about backslashes too so a Windows-style
    // traversal cannot slip through on any platform.
    if raw.contains('\\') || raw.contains('\0') {
        return None;
    }
    let path = Path::new(raw);
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            _ => return None,
        }
    }
    if out.as_os_str().is_empty() {
        return None;
    }
    Some(out)
}

/// Records the plugin's identity and the manifest of the release now running.
/// An update keeps the agent.
pub(crate) async fn create_plugin_meta(
    store: &Db,
    key: &PluginMetaKey,
    manifest: &Manifest,
    plugin_subject: &str,
    release_id: &str,
    previous: Option<&PluginMeta>,
) -> AtomicResult<Agent> {
    let agent: Agent = if let Some(previous) = previous {
        Agent::from_secret(&previous.agent_secret)?
    } else {
        let new_agent = Agent::new(Some(&key.name))?;

        let mut agent_resource = new_agent.to_resource()?;
        let full_name = format!("{}/{}", key.namespace, key.name);
        agent_resource
            .set(
                urls::NAME.into(),
                atomic_lib::Value::String(full_name),
                store,
            )
            .await?;
        agent_resource.save_locally(store).await?;

        new_agent
    };

    store.set_plugin_meta(
        key,
        &PluginMeta {
            subject: plugin_subject.to_string(),
            agent_secret: agent.build_secret()?.clone(),
            manifest: serde_json::to_value(manifest)?,
            release_id: Some(release_id.to_string()),
        },
    )?;

    Ok(agent)
}

/// Removes a plugin's metadata and its agent resource.
pub async fn delete_plugin_meta(
    store: &Db,
    drive_subject: &str,
    namespace: &str,
    name: &str,
) -> AtomicResult<()> {
    let key = PluginMetaKey::new(drive_subject, namespace, name);

    let Some(plugin_meta) = store.get_plugin_meta(&key)? else {
        // The plugin does not have any metadata so we don't have to delete anything.
        return Ok(());
    };

    // Delete the agent resource
    let agent = Agent::from_secret(&plugin_meta.agent_secret)?;
    let mut agent_resource = store.get_resource(&agent.subject.clone()).await?;
    agent_resource.destroy(store).await?;

    // Delete the plugin metadata
    store.delete_plugin_meta(&key)?;

    Ok(())
}

/// The compiled component: the one cached under the hash of its bytes when it
/// still loads, else a fresh compile that is saved for next time. The cache is
/// what keeps a restart from recompiling every module.
fn load_component(
    engine: &Engine,
    wasm_bytes: &[u8],
    cache_dir: &Path,
) -> AtomicResult<(Component, PathBuf)> {
    std::fs::create_dir_all(cache_dir).ok();
    let cwasm_path = cache_dir.join(format!("{}.cwasm", blake3::hash(wasm_bytes).to_hex()));
    if let Ok(bytes) = std::fs::read(&cwasm_path) {
        // Safety: We trust the pre-compiled component on disk as it is generated by us or the admin
        match unsafe { Component::deserialize(engine, &bytes) } {
            Ok(component) => return Ok((component, cwasm_path)),
            Err(e) => warn!(
                "Failed to deserialize cwasm at {}, recompiling. Error: {}",
                cwasm_path.display(),
                e
            ),
        }
    }

    let component_bytes = engine
        .precompile_component(wasm_bytes)
        .map_err(|e| AtomicError::from(format!("Failed to precompile component: {}", e)))?;
    if let Err(e) = std::fs::write(&cwasm_path, &component_bytes) {
        warn!(
            "Failed to write cwasm file to {}: {}",
            cwasm_path.display(),
            e
        );
    }
    let component = unsafe { Component::deserialize(engine, &component_bytes) }.map_err(|e| {
        AtomicError::from(format!("Failed to deserialize compiled component: {}", e))
    })?;
    Ok((component, cwasm_path))
}

/// A module runs as its Installation's agent, which is the identity
/// `installation::resolve` looks up. A plugin installed as a class extender
/// keeps its key in `PluginMeta`; this makes the same key the Installation's.
fn bind_installation_agent(db: &Db, drive: &str, subject: &str, agent: &Agent) -> AtomicResult<()> {
    let key = AppAgentKey::new(drive, subject);
    match db.get_app_agent_state(&key)? {
        AppAgentState::Legacy => db.set_app_agent(
            &key,
            &AppAgent::new(
                agent.subject.to_string(),
                agent.build_secret()?,
                atomic_lib::utils::now(),
            ),
        )?,
        AppAgentState::Active(_) => {}
        AppAgentState::Revoked => {
            return Err(AtomicError::from(
                "this installation's identity was revoked; create a new Installation",
            ))
        }
    }
    Ok(())
}

/// Deletes the compiled components no module loaded at boot used, and the
/// per-drive folders an earlier layout of this cache kept.
fn prune_cache(cache_dir: &Path, used_files: &HashSet<PathBuf>) {
    for old in ["global", "scoped"] {
        std::fs::remove_dir_all(cache_dir.join(old)).ok();
    }
    let Ok(entries) = std::fs::read_dir(cache_dir) else {
        return;
    };
    for path in entries.flatten().map(|entry| entry.path()) {
        if path.extension() == Some(OsStr::new("cwasm")) && !used_files.contains(&path) {
            match std::fs::remove_file(&path) {
                Ok(()) => info!("Deleted unused cwasm file: {}", path.display()),
                Err(e) => warn!(
                    "Failed to delete unused cwasm file {}: {}",
                    path.display(),
                    e
                ),
            }
        }
    }
}

#[cfg(test)]
mod path_safety_tests {
    use super::*;

    #[test]
    fn safe_relative_path_rejects_traversal() {
        assert!(safe_relative_path("../x").is_none());
        assert!(safe_relative_path("a/../../x").is_none());
        assert!(safe_relative_path("/etc/passwd").is_none());
        assert!(safe_relative_path("a\\..\\b").is_none());
        assert!(safe_relative_path("").is_none());
        assert_eq!(
            safe_relative_path("img/logo.png"),
            Some(PathBuf::from("img/logo.png"))
        );
    }
}
