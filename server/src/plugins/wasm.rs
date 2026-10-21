//! Installing server modules (class extenders): the zip, the files on disk and
//! the extender registration. The component itself runs in
//! [`super::host_abi::ServerModule`].

use futures::future::join_all;
use zip::ZipArchive;

use std::{
    collections::HashSet,
    ffi::OsStr,
    path::{Path, PathBuf},
    sync::Arc,
};

use atomic_lib::{
    agents::Agent,
    class_extender::{ClassExtender, ClassExtenderScope},
    db::app_agent::{AppAgent, AppAgentKey, AppAgentState},
    db::plugin_meta::{validate_plugin_identifiers, PermissionType, PluginManifest, PluginMeta},
    errors::{AtomicError, AtomicResult},
    urls, Db, Storelike,
};
use base64::{engine::general_purpose, Engine as _};
use ring::digest::{digest, SHA256};
use tracing::{error, info, warn};
use wasmtime::{component::Component, Engine};

use atomic_lib::db::plugin_meta::PluginMetaKey;

use super::host_abi::{HostAbiRegistry, ModuleParts, ServerModule};
use super::host_core;
use super::manifest::Manifest;

const CLASS_EXTENDER_DIR_NAME: &str = "class-extenders"; // Relative to the store path.

pub async fn load_wasm_class_extenders(
    plugin_path: &Path,
    plugin_cache_path: &Path,
    db: &Db,
    registry: &Arc<HostAbiRegistry>,
) -> AtomicResult<Vec<ClassExtender>> {
    // Create the plugin directory if it doesn't exist
    let plugin_dir = plugin_path.join(CLASS_EXTENDER_DIR_NAME);
    let global_dir = plugin_dir.join("global");
    let scoped_dir = plugin_dir.join("scoped");

    if !plugin_dir.exists() {
        if let Err(err) = std::fs::create_dir_all(&plugin_dir) {
            warn!(
                error = %err,
                path = %plugin_dir.display(),
                "Failed to create Wasm extender directory"
            );
        } else {
            // Create global and scoped directories
            std::fs::create_dir_all(&global_dir).ok();
            std::fs::create_dir_all(&scoped_dir).ok();
            info!(
                path = %plugin_dir.display(),
                "Created empty Wasm extender directory (drop .wasm files in 'global' or 'scoped/<base64_drive_url>' folders)"
            );
        }
        return Ok(Vec::new());
    }

    // Ensure subdirectories exist
    if !global_dir.exists() {
        std::fs::create_dir_all(&global_dir).ok();
    }
    if !scoped_dir.exists() {
        std::fs::create_dir_all(&scoped_dir).ok();
    }

    // Setup cache directories
    if !plugin_cache_path.exists() {
        if let Err(err) = std::fs::create_dir_all(plugin_cache_path) {
            warn!(
                error = %err,
                path = %plugin_cache_path.display(),
                "Failed to create Wasm cache directory"
            );
        }
    }
    let global_cache = plugin_cache_path.join("global");
    if !global_cache.exists() {
        std::fs::create_dir_all(&global_cache).ok();
    }
    let scoped_cache = plugin_cache_path.join("scoped");
    if !scoped_cache.exists() {
        std::fs::create_dir_all(&scoped_cache).ok();
    }

    let engine = match host_core::engine() {
        Ok(engine) => engine,
        Err(err) => {
            error!(error = %err, "Failed to initialize Wasm engine. Skipping dynamic class extenders");
            return Ok(Vec::new());
        }
    };

    let mut extenders = Vec::new();
    let mut used_cwasm_files = HashSet::new();
    let mut cache_dirs = vec![global_cache.clone()];

    info!("Loading plugins...");

    let mut tasks = Vec::new();

    // Global Plugins
    let global_wasm_files = find_wasm_files(&global_dir);
    for path in global_wasm_files {
        tasks.push((
            path,
            global_dir.clone(),
            global_cache.clone(),
            ClassExtenderScope::Global,
        ));
    }

    // Scoped Plugins
    if let Ok(entries) = std::fs::read_dir(&scoped_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let dir_name = entry.file_name();
                let dir_name_str = dir_name.to_string_lossy();

                // Get the scope subject from the directory name
                let Ok(sope_subject) = decode_subject(&dir_name_str) else {
                    warn!(
                        "Skipping invalid base64 scoped plugin directory: {}",
                        dir_name_str
                    );
                    continue;
                };

                let scope = ClassExtenderScope::Drive(sope_subject);
                let drive_wasm_files = find_wasm_files(&path);
                let drive_cache = scoped_cache.join(&dir_name);
                if !drive_cache.exists() {
                    std::fs::create_dir_all(&drive_cache).ok();
                }
                cache_dirs.push(drive_cache.clone());

                for wasm_path in drive_wasm_files {
                    tasks.push((wasm_path, path.clone(), drive_cache.clone(), scope.clone()));
                }
            }
        }
    }

    let futures = tasks
        .into_iter()
        .map(|(path, plugin_dir, plugin_cache_path, scope)| {
            let engine = engine.clone();
            let db = db.clone();
            let registry = registry.clone();

            async move {
                load_plugin_from_disk(
                    &path,
                    &plugin_dir,
                    &plugin_cache_path,
                    scope,
                    engine,
                    &db,
                    registry,
                )
                .await
                .unwrap_or((None, PathBuf::new()))
            }
        });

    let results = join_all(futures).await;

    for res in results {
        let (extender_opt, cwasm_path) = res;
        used_cwasm_files.insert(cwasm_path);
        if let Some(extender) = extender_opt {
            extenders.push(extender);
        }
    }

    for cache_dir in cache_dirs {
        cleanup_cache(&cache_dir, &used_cwasm_files);
    }

    Ok(extenders)
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

fn extract_plugin_to_disk(
    zip: &mut ZipArchive<std::io::Cursor<Vec<u8>>>,
    plugins_dir: &Path,
    encoded_subject: &str,
    namespace: &str,
    name: &str,
) -> AtomicResult<PathBuf> {
    let target_dir = plugins_dir
        .join(CLASS_EXTENDER_DIR_NAME)
        .join("scoped")
        .join(encoded_subject);

    // We do not clear the directory, as multiple plugins might share this scope.
    // Existing files (wasm, json) will be overwritten by zip extraction.
    // The assets directory will be merged (existing files kept, new files written/overwritten).
    std::fs::create_dir_all(&target_dir)
        .map_err(|e| AtomicError::from(format!("Failed to create plugin directory: {}", e)))?;

    for i in 0..zip.len() {
        let mut file = zip
            .by_index(i)
            .map_err(|e| AtomicError::from(e.to_string()))?;
        let file_name = file.name().to_string();

        let target_path = if file_name == "plugin.wasm" {
            target_dir.join(format!("{}.{}.wasm", namespace, name))
        } else if file_name == "plugin.json" {
            target_dir.join(format!("{}.{}.json", namespace, name))
        } else if file_name == "ui.js" {
            target_dir.join(format!("{}.{}.ui.js", namespace, name))
        } else if file_name == "ui.css" {
            target_dir.join(format!("{}.{}.ui.css", namespace, name))
        } else if file_name.starts_with("assets/") {
            // Replace "assets/" with "{namespace}/"
            let stripped = file_name.strip_prefix("assets/").unwrap();
            let assets_dir = target_dir.join(namespace);
            if stripped.is_empty() {
                // It is the "assets/" directory itself
                assets_dir
            } else {
                // Zip entry names are attacker-controlled: reject anything that is not a
                // plain relative path made of normal components (no `..`, no absolute paths).
                let relative = safe_relative_path(stripped).ok_or_else(|| {
                    AtomicError::from(format!(
                        "Plugin zip contains an unsafe asset path: {}",
                        file_name
                    ))
                })?;
                assets_dir.join(relative)
            }
        } else {
            continue;
        };

        if file.is_dir() {
            std::fs::create_dir_all(&target_path).map_err(|e| {
                AtomicError::from(format!(
                    "Failed to create directory {}: {}",
                    target_path.display(),
                    e
                ))
            })?;
        } else {
            if let Some(parent) = target_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    AtomicError::from(format!(
                        "Failed to create directory {}: {}",
                        parent.display(),
                        e
                    ))
                })?;
            }
            let mut outfile = std::fs::File::create(&target_path).map_err(|e| {
                AtomicError::from(format!(
                    "Failed to create file {}: {}",
                    target_path.display(),
                    e
                ))
            })?;
            std::io::copy(&mut file, &mut outfile).map_err(|e| {
                AtomicError::from(format!(
                    "Failed to write file {}: {}",
                    target_path.display(),
                    e
                ))
            })?;
        }
    }

    Ok(target_dir)
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

/// Errors unless `child` is exactly one path component below `parent`.
fn ensure_direct_child(parent: &Path, child: &Path) -> AtomicResult<()> {
    let is_direct_child = child.parent() == Some(parent)
        && matches!(
            child.components().next_back(),
            Some(std::path::Component::Normal(_))
        );
    if !is_direct_child {
        return Err(AtomicError::from(format!(
            "Refusing to touch path outside plugin directory: {}",
            child.display()
        )));
    }
    Ok(())
}

/// The registry id of a drive-scoped class extender, the same one
/// [`load_plugin_from_disk`] builds for the file it loads.
pub fn scoped_extender_id(drive_subject: &str, namespace: &str, name: &str) -> String {
    format!("{drive_subject}:{namespace}.{name}.wasm")
}

/// Unregisters a drive-scoped extender and leaves everything else alone.
///
/// This is what pausing an Installation does: the hooks stop firing at once,
/// while the files stay on disk and `PluginMeta` keeps the plugin's agent
/// secret, so resuming is a re-registration rather than a fresh install with a
/// new identity. Uninstalling is [`uninstall_plugin`].
pub fn suspend_plugin(
    store: &Db,
    drive_subject: &str,
    namespace: &str,
    name: &str,
) -> AtomicResult<()> {
    validate_plugin_identifiers(namespace, name)?;
    store.remove_class_extender(&scoped_extender_id(drive_subject, namespace, name))
}

/// Registers an extender whose files are already extracted, for an activation
/// that found this exact release materialized.
///
/// A no-op when it is registered already, so the common case (a config change
/// on a running plugin) does not reload the component. Resuming a paused
/// installation is the case that does.
pub async fn register_installed_plugin(
    store: &Db,
    drive_subject: &str,
    namespace: &str,
    name: &str,
    plugins_dir: &Path,
    plugin_cache_dir: &Path,
    registry: &Arc<HostAbiRegistry>,
) -> AtomicResult<()> {
    validate_plugin_identifiers(namespace, name)?;
    let id = scoped_extender_id(drive_subject, namespace, name);
    if store.has_class_extender(&id) {
        return Ok(());
    }

    let encoded_subject = general_purpose::URL_SAFE.encode(drive_subject);
    let target_dir = plugins_dir
        .join(CLASS_EXTENDER_DIR_NAME)
        .join("scoped")
        .join(&encoded_subject);
    let wasm_path = target_dir.join(format!("{namespace}.{name}.wasm"));
    if !wasm_path.exists() {
        return Err(AtomicError::not_found(format!(
            "{namespace}.{name} is recorded as installed but {} is missing",
            wasm_path.display()
        )));
    }

    let scoped_cache = plugin_cache_dir.join("scoped").join(&encoded_subject);
    if !scoped_cache.exists() {
        std::fs::create_dir_all(&scoped_cache).ok();
    }
    let engine = host_core::engine().map_err(AtomicError::from)?;
    let (extender, _) = load_plugin_from_disk(
        &wasm_path,
        &target_dir,
        &scoped_cache,
        ClassExtenderScope::Drive(drive_subject.to_string()),
        engine,
        store,
        registry.clone(),
    )
    .await?;
    let extender = extender.ok_or_else(|| {
        AtomicError::from(format!("could not load the installed {namespace}.{name}"))
    })?;
    store.add_class_extender(extender)
}

pub async fn uninstall_plugin(
    name: &str,
    namespace: &str,
    drive_subject: &str,
    store: &Db,
    plugins_dir: &Path,
) -> AtomicResult<()> {
    // `namespace` and `name` may come straight from a user-controlled Plugin resource
    // (see `plugin.rs`), not only from a validated manifest. They are used to build
    // filesystem paths below, so they must be plain path segments (GHSA-vr56-vwrw-w2vg).
    validate_plugin_identifiers(namespace, name)?;

    let encoded_subject = general_purpose::URL_SAFE.encode(drive_subject);
    let target_dir = plugins_dir
        .join(CLASS_EXTENDER_DIR_NAME)
        .join("scoped")
        .join(&encoded_subject);

    if !target_dir.exists() {
        return Err(AtomicError::not_found(format!(
            "Plugin directory not found for drive: {}",
            drive_subject
        )));
    }

    let wasm_filename = format!("{}.{}.wasm", namespace, name);
    let wasm_path = target_dir.join(&wasm_filename);
    let json_path = target_dir.join(format!("{}.{}.json", namespace, name));
    let ui_js_path = target_dir.join(format!("{}.{}.ui.js", namespace, name));
    let ui_css_path = target_dir.join(format!("{}.{}.ui.css", namespace, name));
    let assets_dir = target_dir.join(namespace);

    // Defense in depth: every path we are about to delete must be a direct child of `target_dir`.
    for path in [
        &wasm_path,
        &json_path,
        &ui_js_path,
        &ui_css_path,
        &assets_dir,
    ] {
        ensure_direct_child(&target_dir, path)?;
    }

    if !wasm_path.exists() {
        return Err(AtomicError::not_found(format!(
            "Plugin {}.{} not found",
            namespace, name
        )));
    }

    // 1. Remove from DB
    store.remove_class_extender(&scoped_extender_id(drive_subject, namespace, name))?;

    // 2. Remove from disk
    std::fs::remove_file(&wasm_path).map_err(|e| {
        AtomicError::from(format!(
            "Failed to remove wasm file {}: {}",
            wasm_path.display(),
            e
        ))
    })?;

    if json_path.exists() {
        std::fs::remove_file(&json_path).map_err(|e| {
            AtomicError::from(format!(
                "Failed to remove json file {}: {}",
                json_path.display(),
                e
            ))
        })?;
    }

    if ui_js_path.exists() {
        std::fs::remove_file(&ui_js_path).map_err(|e| {
            AtomicError::from(format!(
                "Failed to remove ui.js file {}: {}",
                ui_js_path.display(),
                e
            ))
        })?;
    }

    if ui_css_path.exists() {
        std::fs::remove_file(&ui_css_path).map_err(|e| {
            AtomicError::from(format!(
                "Failed to remove ui.css file {}: {}",
                ui_css_path.display(),
                e
            ))
        })?;
    }

    // 3. Handle assets folder
    // Check if other plugins are using the same namespace in this drive
    let mut namespace_still_used = false;
    if let Ok(entries) = std::fs::read_dir(&target_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
                    // Check for other plugins in the same namespace
                    if file_name.starts_with(&format!("{}.", namespace))
                        && (file_name.ends_with(".wasm") || file_name.ends_with(".json"))
                    {
                        namespace_still_used = true;
                        break;
                    }
                }
            }
        }
    }

    if !namespace_still_used && assets_dir.is_dir() {
        info!("Removing unused assets directory: {}", assets_dir.display());
        std::fs::remove_dir_all(&assets_dir).map_err(|e| {
            AtomicError::from(format!(
                "Failed to remove assets directory {}: {}",
                assets_dir.display(),
                e
            ))
        })?;
    }

    delete_plugin_meta(store, drive_subject, namespace, name).await?;

    info!("Uninstalled plugin {}.{}", namespace, name);

    Ok(())
}

/// Materializes a wasip2 package on this drive: extracts the zip into
/// `scoped/<drive>/`, records the plugin's identity and `manifest` (the
/// unified manifest the Installation reviewed, which names the package's
/// namespace and name) and loads the class extender. An update of an already
/// installed package is rolled back to the previous files when any step fails.
#[allow(clippy::too_many_arguments)]
pub async fn install_or_update_plugin(
    zip_file: &mut ZipArchive<std::io::Cursor<Vec<u8>>>,
    drive_subject: &str,
    plugin_subject: &str,
    manifest: &Manifest,
    store: &Db,
    plugins_dir: &Path,
    plugin_cache_dir: &Path,
    registry: &Arc<HostAbiRegistry>,
) -> AtomicResult<()> {
    // 1. Validation
    validate_plugin_zip(zip_file)?;
    let (namespace, name) = manifest_identifiers(manifest)?;

    let wasm_target_name = format!("{namespace}.{name}.wasm");
    let json_target_name = format!("{namespace}.{name}.json");
    let encoded_subject = general_purpose::URL_SAFE.encode(drive_subject);

    // Compute target paths for rollback tracking
    let target_dir = plugins_dir
        .join(CLASS_EXTENDER_DIR_NAME)
        .join("scoped")
        .join(&encoded_subject);
    let wasm_path = target_dir.join(&wasm_target_name);
    let json_path = target_dir.join(&json_target_name);
    let ui_js_path = target_dir.join(format!("{namespace}.{name}.ui.js"));
    let ui_css_path = target_dir.join(format!("{namespace}.{name}.ui.css"));

    // Determine if this is a fresh install or an update by saving the old metadata
    let meta_key = PluginMetaKey::new(drive_subject, namespace, name);
    let old_plugin_meta = store.get_plugin_meta(&meta_key)?;
    let is_update = old_plugin_meta.is_some();

    // Back up existing files before extraction so we can restore them on failure
    let wasm_backup = wasm_path.with_extension("wasm.bak");
    let json_backup = json_path.with_extension("json.bak");
    let ui_js_backup = ui_js_path.with_extension("js.bak");
    let ui_css_backup = ui_css_path.with_extension("css.bak");

    if is_update {
        if wasm_path.exists() {
            std::fs::copy(&wasm_path, &wasm_backup).map_err(|e| {
                AtomicError::from(format!("Failed to back up existing wasm file: {}", e))
            })?;
        }
        if json_path.exists() {
            std::fs::copy(&json_path, &json_backup).map_err(|e| {
                AtomicError::from(format!("Failed to back up existing json file: {}", e))
            })?;
        }
        if ui_js_path.exists() {
            std::fs::copy(&ui_js_path, &ui_js_backup).map_err(|e| {
                AtomicError::from(format!("Failed to back up existing ui.js file: {}", e))
            })?;
        }
        if ui_css_path.exists() {
            std::fs::copy(&ui_css_path, &ui_css_backup).map_err(|e| {
                AtomicError::from(format!("Failed to back up existing ui.css file: {}", e))
            })?;
        }
    }

    // Run the installation steps. If any step fails, we roll back all side effects.
    let result: AtomicResult<()> = async {
        // 2. Extract plugin files to disk
        let target_dir =
            extract_plugin_to_disk(zip_file, plugins_dir, &encoded_subject, namespace, name)?;

        // 3. Create a new agent for the plugin if needed
        create_plugin_meta(store, drive_subject, manifest, plugin_subject).await?;

        // 4. Load Plugin
        let engine = host_core::engine().map_err(AtomicError::from)?;
        let wasm_load_path = target_dir.join(&wasm_target_name);

        let scope = ClassExtenderScope::Drive(drive_subject.to_string());
        let scoped_cache = plugin_cache_dir.join("scoped").join(&encoded_subject);

        if !scoped_cache.exists() {
            std::fs::create_dir_all(&scoped_cache).ok();
        }

        let (plugin, _) = load_plugin_from_disk(
            &wasm_load_path,
            &target_dir,
            &scoped_cache,
            scope,
            engine,
            store,
            registry.clone(),
        )
        .await?;

        if let Some(plugin) = plugin {
            store.add_class_extender(plugin)?;
        } else {
            return Err(AtomicError::from("Failed to load installed plugin"));
        }

        Ok(())
    }
    .await;

    match result {
        Ok(()) => {
            // Success: clean up backup files
            if is_update {
                std::fs::remove_file(&wasm_backup).ok();
                std::fs::remove_file(&json_backup).ok();
                std::fs::remove_file(&ui_js_backup).ok();
                std::fs::remove_file(&ui_css_backup).ok();
            }
            Ok(())
        }
        Err(e) => {
            warn!("Plugin installation failed, rolling back: {}", e);
            rollback_plugin_install(
                store,
                drive_subject,
                namespace,
                name,
                &meta_key,
                old_plugin_meta,
                &wasm_path,
                &json_path,
                &ui_js_path,
                &ui_css_path,
                &wasm_backup,
                &json_backup,
                &ui_js_backup,
                &ui_css_backup,
            )
            .await;
            Err(e)
        }
    }
}

/// Rolls back a failed plugin installation by restoring file backups and metadata
/// (for updates) or removing newly created files and metadata (for fresh installs).
#[allow(clippy::too_many_arguments)]
async fn rollback_plugin_install(
    store: &Db,
    drive_subject: &str,
    namespace: &str,
    name: &str,
    meta_key: &PluginMetaKey,
    old_plugin_meta: Option<PluginMeta>,
    wasm_path: &Path,
    json_path: &Path,
    ui_js_path: &Path,
    ui_css_path: &Path,
    wasm_backup: &Path,
    json_backup: &Path,
    ui_js_backup: &Path,
    ui_css_backup: &Path,
) {
    if let Some(old_meta) = old_plugin_meta {
        // Update: restore backed up files
        if wasm_backup.exists() {
            if let Err(e) = std::fs::rename(wasm_backup, wasm_path) {
                error!("Rollback: failed to restore wasm backup: {}", e);
            }
        }
        if json_backup.exists() {
            if let Err(e) = std::fs::rename(json_backup, json_path) {
                error!("Rollback: failed to restore json backup: {}", e);
            }
        }
        if ui_js_backup.exists() {
            if let Err(e) = std::fs::rename(ui_js_backup, ui_js_path) {
                error!("Rollback: failed to restore ui.js backup: {}", e);
            }
        }
        if ui_css_backup.exists() {
            if let Err(e) = std::fs::rename(ui_css_backup, ui_css_path) {
                error!("Rollback: failed to restore ui.css backup: {}", e);
            }
        }

        // Restore the old plugin metadata
        if let Err(e) = store.set_plugin_meta(meta_key, &old_meta) {
            error!("Rollback: failed to restore plugin metadata: {}", e);
        }
    } else {
        // Fresh install: remove newly created files
        if wasm_path.exists() {
            std::fs::remove_file(wasm_path).ok();
        }
        if json_path.exists() {
            std::fs::remove_file(json_path).ok();
        }
        if ui_js_path.exists() {
            std::fs::remove_file(ui_js_path).ok();
        }
        if ui_css_path.exists() {
            std::fs::remove_file(ui_css_path).ok();
        }

        // Clean up metadata that was created during this failed install
        if let Err(e) = delete_plugin_meta(store, drive_subject, namespace, name).await {
            error!("Rollback: failed to delete plugin metadata: {}", e);
        }
    }
}

async fn create_plugin_meta(
    store: &Db,
    drive_subject: &str,
    manifest: &Manifest,
    plugin_subject: &str,
) -> AtomicResult<()> {
    let (namespace, name) = manifest_identifiers(manifest)?;

    let key = PluginMetaKey::new(drive_subject, namespace, name);
    let plugin_meta = store.get_plugin_meta(&key)?;

    // An update keeps the identity.
    let agent: Agent = if let Some(plugin_meta) = plugin_meta {
        Agent::from_secret(&plugin_meta.agent_secret)?
    } else {
        // If the plugin meta does not exist yet we create a new agent.
        let new_agent = Agent::new(Some(name))?;

        let mut agent_resource = new_agent.to_resource()?;
        let full_name = format!("{}/{}", namespace, name);
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
        &key,
        &PluginMeta {
            subject: plugin_subject.to_string(),
            agent_secret: agent.build_secret()?.clone(),
            manifest: serde_json::to_value(manifest)?,
            // Which release these bytes are is the Installation's business;
            // `installation_hook::activate` records it once the files are down.
            release_id: None,
        },
    )?;

    Ok(())
}

async fn delete_plugin_meta(
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

async fn load_plugin_from_disk(
    path: &Path,
    plugin_dir: &Path,
    plugin_cache_path: &Path,
    scope: ClassExtenderScope,
    engine: Arc<Engine>,
    db: &Db,
    registry: Arc<HostAbiRegistry>,
) -> AtomicResult<(Option<ClassExtender>, PathBuf)> {
    let owned_folder_path = setup_plugin_data_dir(path, plugin_dir);

    let wasm_bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to read Wasm file at {}: {}", path.display(), e);
            return Ok((None, PathBuf::new())); // Or return Error? Original code returned None.
        }
    };

    // Attempt to find the plugin subject from the store metadata
    let (plugin_subject, agent, manifest) = match &scope {
        ClassExtenderScope::Drive(drive_subject) => {
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let stem_path = Path::new(stem);
            let namespace = stem_path.file_stem().and_then(|s| s.to_str());
            let name = stem_path.extension().and_then(|s| s.to_str());

            let (Some(namespace), Some(name)) = (namespace, name) else {
                return Err(AtomicError::from(format!(
                    "Invalid plugin filename (expected namespace.name.wasm): {}",
                    path.display()
                )));
            };

            let key = PluginMetaKey::new(drive_subject, namespace, name);
            let meta = db.get_plugin_meta(&key).map_err(|e| {
                AtomicError::from(format!("Failed to get plugin metadata from store: {}", e))
            })?;

            let Some(m) = meta else {
                return Err(AtomicError::from(format!(
                    "Plugin metadata not found in store for {}.{}",
                    namespace, name
                )));
            };

            let agent = Agent::from_secret(&m.agent_secret)?;
            let manifest = unified_manifest(db, &key, m, &wasm_bytes).await?;
            bind_installation_agent(db, drive_subject, &manifest.0, &agent)?;

            (Some(manifest.0), Some(agent), Some(manifest.1))
        }
        ClassExtenderScope::Global => (None, None, None),
    };

    let hash = digest(&SHA256, &wasm_bytes);
    let hash_hex = hex_encode(hash.as_ref());
    let cwasm_filename = format!("{}.cwasm", hash_hex);
    let cwasm_path = plugin_cache_path.join(cwasm_filename);
    let cwasm_path_ret = cwasm_path.clone();

    let loaded = async {
        let component = load_component(&engine, &wasm_bytes, path, &cwasm_path)?;
        let parts = ModuleParts {
            file_name: path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string(),
            scope,
            installation: plugin_subject,
            agent,
            data_dir: owned_folder_path,
            manifest,
            registry,
        };
        ServerModule::new(engine, component, db, parts).await
    }
    .await;

    match loaded {
        Ok(module) => {
            info!(
                "Loaded {}",
                path.file_name().unwrap_or(OsStr::new("Unknown")).display()
            );
            Ok((Some(module.into_class_extender()), cwasm_path_ret))
        }
        Err(err) => {
            error!(
                error = %err,
                path = %path.display(),
                "Failed to load Wasm class extender"
            );
            Ok((None, cwasm_path_ret))
        }
    }
}

/// The compiled component: the cached one when it still loads, else a fresh
/// compile that is saved for next time.
fn load_component(
    engine: &Engine,
    wasm_bytes: &[u8],
    path: &Path,
    cwasm_path: &Path,
) -> AtomicResult<Component> {
    let Ok(bytes) = std::fs::read(cwasm_path) else {
        return compile_and_save_component(engine, wasm_bytes, path, cwasm_path);
    };
    // Safety: We trust the pre-compiled component on disk as it is generated by us or the admin
    match unsafe { Component::deserialize(engine, &bytes) } {
        Ok(component) => Ok(component),
        Err(e) => {
            warn!(
                "Failed to deserialize cwasm at {}, recompiling. Error: {}",
                cwasm_path.display(),
                e
            );
            compile_and_save_component(engine, wasm_bytes, path, cwasm_path)
        }
    }
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

fn compile_and_save_component(
    engine: &Engine,
    wasm_bytes: &[u8],
    wasm_path: &Path,
    cwasm_path: &Path,
) -> AtomicResult<Component> {
    info!(
        "Pre-compiling {}",
        wasm_path
            .file_name()
            .unwrap_or(OsStr::new("Unknown"))
            .display()
    );

    let component_bytes = engine
        .precompile_component(wasm_bytes)
        .map_err(|e| AtomicError::from(format!("Failed to precompile component: {}", e)))?;

    if let Err(e) = std::fs::write(cwasm_path, &component_bytes) {
        warn!(
            "Failed to write cwasm file to {}: {}",
            cwasm_path.display(),
            e
        );
    } else {
        info!("Saved pre-compiled component to {}", cwasm_path.display());
    }

    unsafe { Component::deserialize(engine, &component_bytes) }
        .map_err(|e| AtomicError::from(format!("Failed to deserialize compiled component: {}", e)))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn cleanup_cache(cache_dir: &Path, used_files: &HashSet<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(cache_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension() == Some(std::ffi::OsStr::new("cwasm"))
                && !used_files.contains(&path)
            {
                if let Err(e) = std::fs::remove_file(&path) {
                    warn!(
                        "Failed to delete unused cwasm file {}: {}",
                        path.display(),
                        e
                    );
                } else {
                    info!("Deleted unused cwasm file: {}", path.display());
                }
            }
        }
    }
}

fn decode_subject(b64_subject: &str) -> AtomicResult<String> {
    let subject = String::from_utf8(
        general_purpose::URL_SAFE
            .decode(b64_subject.as_bytes())
            .map_err(|e| AtomicError::from(format!("Failed to decode subject: {}", e)))?,
    )
    .map_err(|e| AtomicError::from(format!("Failed to decode subject: {}", e)))?;

    Ok(subject)
}

/// The installed plugin's unified manifest, and its resource subject.
///
/// A record written before manifests were unified holds the untranslated
/// `plugin.json`. It is translated once, with the classes the component itself
/// exports (the only thing `plugin.json` does not say), and written back, so
/// every later read finds the unified form.
async fn unified_manifest(
    db: &Db,
    key: &PluginMetaKey,
    meta: PluginMeta,
    wasm_bytes: &[u8],
) -> AtomicResult<(String, Manifest)> {
    if meta.has_v2_manifest() {
        let manifest = Manifest::parse(meta.manifest).map_err(|e| {
            AtomicError::from(format!(
                "stored manifest of {}.{} is invalid: {e}",
                key.namespace, key.name
            ))
        })?;
        return Ok((
            meta.subject,
            manifest.expect("a manifest with a schemaVersion"),
        ));
    }
    let plugin_json: PluginManifest = serde_json::from_value(meta.manifest).map_err(|e| {
        AtomicError::from(format!(
            "stored plugin.json of {}.{} is invalid: {e}",
            key.namespace, key.name
        ))
    })?;
    let class_urls = read_class_urls(db, wasm_bytes).await?;
    let manifest = translate_plugin_json(&plugin_json, &class_urls)?;
    info!(
        "translated the stored plugin.json of {}.{} into the unified manifest",
        key.namespace, key.name
    );
    db.set_plugin_meta(
        key,
        &PluginMeta {
            subject: meta.subject.clone(),
            agent_secret: meta.agent_secret,
            manifest: serde_json::to_value(&manifest)?,
            release_id: meta.release_id,
        },
    )?;
    Ok((meta.subject, manifest))
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

    #[test]
    fn ensure_direct_child_rejects_escapes() {
        let parent = Path::new("/plugins/scoped/abc");
        assert!(ensure_direct_child(parent, &parent.join("ns.name.wasm")).is_ok());
        assert!(ensure_direct_child(parent, &parent.join("../x")).is_err());
        assert!(ensure_direct_child(parent, &parent.join("a/b")).is_err());
        assert!(ensure_direct_child(parent, parent).is_err());
    }

    /// Regression test for GHSA-vr56-vwrw-w2vg: a traversal payload in namespace/name must
    /// never delete anything outside the drive's scoped plugin directory.
    #[tokio::test]
    async fn uninstall_rejects_path_traversal() {
        let db = Db::init_temp("uninstall_rejects_path_traversal")
            .await
            .unwrap();
        let (_agent, drive) = db.setup("Attacker").await.unwrap();

        let plugins_dir =
            std::env::temp_dir().join(format!("atomic_uninstall_traversal_{}", std::process::id()));
        let victim_dir = plugins_dir.join("victim");
        std::fs::create_dir_all(&victim_dir).unwrap();
        let victim_file = victim_dir.join("target.wasm");
        std::fs::write(&victim_file, b"do not delete").unwrap();

        let encoded_subject = general_purpose::URL_SAFE.encode(&drive);
        let target_dir = plugins_dir
            .join(CLASS_EXTENDER_DIR_NAME)
            .join("scoped")
            .join(&encoded_subject);
        std::fs::create_dir_all(&target_dir).unwrap();

        // Traverses from target_dir up to plugins_dir/victim/target.wasm
        let result =
            uninstall_plugin("target", "../../../victim/", &drive, &db, &plugins_dir).await;
        assert!(result.is_err(), "traversal namespace must be rejected");
        assert!(victim_file.exists(), "victim file must not be deleted");

        // Same for the assets dir branch: namespace resolving to a directory outside target_dir.
        let result = uninstall_plugin("target", "../../../victim", &drive, &db, &plugins_dir).await;
        assert!(result.is_err());
        assert!(victim_dir.exists(), "victim directory must not be deleted");

        std::fs::remove_dir_all(&plugins_dir).ok();
    }
}
