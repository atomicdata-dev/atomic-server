//! Installation: the one install path for both plugin runtimes.
//!
//! Committing an `Installation` with `installationStatus: active` resolves the
//! pinned Release, verifies its id, refuses what an Installation may not carry,
//! checks the grants and then materializes by runtime: a wasip2 package is
//! extracted into `scoped/<drive>/` and loaded as a class extender; a JS
//! release only needs its installation identity. `revoked` or destroy undoes
//! both.
//!
//! The legacy `Plugin` + `pluginFile` resources that predate Installations are
//! migrated once at startup by [`migrate_legacy_plugins`]; there is no install
//! hook for them any more.

#[cfg(feature = "wasm-plugins")]
use std::path::Path;
use std::path::PathBuf;

use atomic_lib::{
    agents::{Agent, ForAgent},
    class_extender::{BoxFuture, ClassExtender, CommitExtenderContext, GetExtenderContext},
    db::plugin_meta::{validate_plugin_identifiers, PluginMetaKey},
    errors::AtomicResult,
    storelike::ResourceResponse,
    urls, AtomicError, Db, Resource, Storelike, Value,
};

pub const STATUS_DRAFT: &str = "draft";
pub const STATUS_ACTIVE: &str = "active";
pub const STATUS_PAUSED: &str = "paused";
pub const STATUS_REVOKED: &str = "revoked";

async fn get_parent_drive(resource: &Resource, store: &Db) -> AtomicResult<String> {
    // Loro materialization decodes scalar string values as `Value::String`,
    // not `Value::AtomicUrl` — there's no type marker in the stored string.
    // Accept either so genesis commits (where the only source of state is
    // the loroUpdate) don't fail their before-commit hook.
    let parent_subject = match resource.get(urls::PARENT) {
        Ok(Value::AtomicUrl(s)) => s.to_string(),
        Ok(Value::String(s)) => s.clone(),
        _ => {
            return Err(AtomicError::from(format!(
                "Installation {} has no parent",
                resource.get_subject()
            )));
        }
    };

    let parent_resource = store
        .get_resource_extended(&parent_subject.clone().into(), true, &ForAgent::Sudo)
        .await?
        .to_single();

    if !parent_resource
        .get(urls::IS_A)?
        .to_subjects(None)?
        .contains(&urls::DRIVE.to_string())
    {
        return Err(AtomicError::from(format!(
            "Parent resource for installation {} is not a drive",
            resource.get_subject()
        )));
    };

    Ok(parent_subject)
}

fn string_value(resource: &Resource, prop: &str) -> Option<String> {
    match resource.get(prop) {
        Ok(Value::AtomicUrl(s)) => Some(s.to_string()),
        Ok(Value::String(s)) => Some(s.clone()),
        Ok(other) => Some(other.to_string()),
        Err(_) => None,
    }
}

/// The namespace and name on the resource, validated as path segments.
fn get_namespace_and_name(resource: &Resource) -> AtomicResult<(String, String)> {
    let name = string_value(resource, urls::NAME).ok_or_else(|| {
        AtomicError::from(format!("Plugin {} has no name", resource.get_subject()))
    })?;
    let namespace = string_value(resource, urls::NAMESPACE).ok_or_else(|| {
        AtomicError::from(format!(
            "Plugin {} has no namespace",
            resource.get_subject()
        ))
    })?;
    // These values are user-controlled and end up in filesystem paths.
    validate_plugin_identifiers(&namespace, &name)?;
    Ok((namespace, name))
}

/// The legacy `pluginPermissions` shape, `[{permission, reason}]`, derived
/// from a unified manifest's `capabilities` and `network`. A manifest that is
/// still an untranslated `plugin.json` carries `permissions` in that shape.
fn permissions_view(manifest: &serde_json::Value) -> Option<serde_json::Value> {
    if let Some(legacy) = manifest.get("permissions") {
        return Some(legacy.clone());
    }
    let mut permissions: Vec<serde_json::Value> = manifest
        .get("capabilities")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|capability| {
            let (name, reason) = match capability {
                serde_json::Value::String(name) => (name.as_str(), None),
                serde_json::Value::Object(map) => (
                    map.get("name").and_then(|v| v.as_str())?,
                    map.get("reason").and_then(|v| v.as_str()),
                ),
                _ => return None,
            };
            Some(serde_json::json!({"permission": name, "reason": reason.unwrap_or_default()}))
        })
        .collect();
    let network = manifest.get("network");
    if network
        .and_then(|n| n.get("origins"))
        .and_then(|o| o.as_array())
        .is_some_and(|origins| !origins.is_empty())
    {
        let reason = network
            .and_then(|n| n.get("reason"))
            .and_then(|r| r.as_str())
            .unwrap_or_default();
        permissions.push(serde_json::json!({"permission": "network", "reason": reason}));
    }
    (!permissions.is_empty()).then_some(serde_json::Value::Array(permissions))
}

/// Serves an Installation with what the server knows about it: the agent it
/// acts as, and the version, description, author, permissions and config
/// schema of the manifest it was installed with.
fn on_resource_get(context: GetExtenderContext) -> BoxFuture<AtomicResult<ResourceResponse>> {
    Box::pin(async move {
        let GetExtenderContext {
            store, db_resource, ..
        } = context;

        let drive = get_parent_drive(db_resource, store).await?;

        // A resource with missing or invalid identifiers has no meta to enrich it with.
        // Return it untouched so it can still be viewed and deleted.
        let Ok((namespace, name)) = get_namespace_and_name(db_resource) else {
            return Ok(db_resource.clone().into());
        };

        let Some(meta) = store.get_plugin_meta(&PluginMetaKey::new(&drive, &namespace, &name))?
        else {
            return Ok(db_resource.clone().into());
        };

        let agent = Agent::from_secret(&meta.agent_secret)?;
        db_resource.set_unsafe(
            urls::PLUGIN_AGENT.to_string(),
            Value::AtomicUrl(agent.subject.clone()),
        )?;

        let manifest = &meta.manifest;
        let text = |key: &str| {
            manifest
                .get(key)
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };
        if let Some(version) = text("version") {
            db_resource
                .set(urls::VERSION.to_string(), Value::String(version), store)
                .await?;
        }
        if let Some(description) = text("description") {
            db_resource
                .set(
                    urls::DESCRIPTION.to_string(),
                    Value::Markdown(description),
                    store,
                )
                .await?;
        }
        if let Some(author) = text("author") {
            db_resource
                .set(
                    urls::PLUGIN_AUTHOR.to_string(),
                    Value::String(author),
                    store,
                )
                .await?;
        }
        if let Some(permissions) = permissions_view(manifest) {
            db_resource
                .set(
                    urls::PLUGIN_PERMISSIONS.to_string(),
                    Value::Json(permissions),
                    store,
                )
                .await?;
        }
        if let Some(schema) = manifest.get("configSchema").filter(|s| s.is_object()) {
            db_resource
                .set(
                    urls::JSON_SCHEMA.to_string(),
                    Value::Json(schema.clone()),
                    store,
                )
                .await?;
        }

        Ok(db_resource.clone().into())
    })
}

#[cfg(feature = "wasm-plugins")]
mod installation_hook {
    use super::*;
    use crate::plugins::{
        manifest::Manifest,
        release,
        wasm::{
            describe_package, install_or_update_plugin, register_installed_plugin, suspend_plugin,
            uninstall_plugin,
        },
    };
    use atomic_lib::db::{
        app_agent::{AppAgent, AppAgentKey, AppAgentState},
        plugin_meta::PluginMeta,
        plugin_release::{PluginRelease, WORLD_SERVER_EXTENSION},
    };
    use tracing::info;
    use zip::ZipArchive;

    fn json_value(resource: &Resource, prop: &str) -> AtomicResult<serde_json::Value> {
        match resource.get(prop) {
            Ok(Value::Json(v)) => Ok(v.clone()),
            Ok(Value::String(s)) => Ok(serde_json::from_str(s)?),
            Ok(other) => Ok(serde_json::from_str(&other.to_string())?),
            Err(_) => Ok(serde_json::Value::Null),
        }
    }

    /// Namespace and name identify the installation on the drive. They come
    /// from the resource, or from the manifest when the resource has none;
    /// when both name them they must agree, since the package is extracted
    /// under the manifest's names and the resource is found by its own.
    pub(super) fn identifiers(
        resource: &Resource,
        manifest: &serde_json::Value,
    ) -> AtomicResult<(String, String)> {
        let pick = |prop: &str, key: &str, what: &str| -> AtomicResult<String> {
            let declared = manifest.get(key).and_then(|v| v.as_str());
            match (string_value(resource, prop), declared) {
                (Some(own), Some(declared)) if own != declared => Err(AtomicError::from(format!(
                    "the Installation's {what} '{own}' differs from the release manifest's '{declared}'"
                ))),
                (Some(own), _) => Ok(own),
                (None, Some(declared)) => Ok(declared.to_string()),
                (None, None) => Err(AtomicError::from(format!(
                    "an Installation needs a {what}, on the resource or in the manifest"
                ))),
            }
        };
        let namespace = pick(urls::NAMESPACE, "namespace", "namespace")?;
        let name = pick(urls::NAME, "name", "name")?;
        validate_plugin_identifiers(&namespace, &name)?;
        Ok((namespace, name))
    }

    pub async fn activate(
        resource: &Resource,
        drive: &str,
        store: &Db,
        signer: &str,
        plugins_dir: &Path,
        plugin_cache_dir: &Path,
    ) -> AtomicResult<()> {
        let subject = resource.get_subject().to_string();
        let reference = string_value(resource, urls::RELEASE_PROP)
            .ok_or("an active Installation needs a release")?;
        let pinned = string_value(resource, urls::RELEASE_ID)
            .ok_or("an active Installation needs a releaseId")?;

        // 1. Resolve and verify. The pinned id is what the installer reviewed;
        //    whatever the reference resolves to must hash to exactly that.
        let for_agent = ForAgent::AgentSubject(signer.to_string().into());
        let release = release::resolve(store, &reference, &for_agent).await?;
        let actual = release.id()?;
        if actual != pinned {
            return Err(AtomicError::from(format!(
                "Installation {subject} pins release {pinned} but {reference} resolves to {actual}; refusing to install"
            )));
        }
        // A wasip2 server-extension is a class extender; an Installation
        // materializes it drive-scoped (`scoped/<drive>/`), so its hooks only
        // see this drive. A JS server-extension has no runtime that serves its
        // hooks yet, and a server-scoped extension is configured by the
        // operator on disk, never through a commit.
        if release.world == WORLD_SERVER_EXTENSION && !release.is_wasip2() {
            return Err(AtomicError::from(
                "a server-extension release cannot be installed through an Installation; operators configure it on the server",
            ));
        }

        // 2. Grants against what the manifest declares. The grants on the
        //    Installation are the approved set the host reads back.
        release::check_grants(&release.manifest, &json_value(resource, urls::GRANTS)?)?;

        let (namespace, name) = identifiers(resource, &release.manifest)?;
        let key = PluginMetaKey::new(drive, &namespace, &name);
        let existing = store.get_plugin_meta(&key)?;
        if let Some(meta) = &existing {
            if meta.subject != subject {
                return Err(AtomicError::from(format!(
                    "'{namespace}/{name}' is already installed on this drive by {}",
                    meta.subject
                )));
            }
        }

        // 3. Materialize by runtime.
        if release.is_wasip2() {
            // The exact release whose code is already on disk, by id: a config
            // change or the legacy migration then extracts and compiles
            // nothing again. Comparing manifests instead would be wrong, since
            // two releases of one plugin can agree on every manifest field and
            // differ in their package bytes. A record from before the id was
            // stored says nothing about what is on disk, so it materializes.
            let materialized = existing
                .as_ref()
                .and_then(|meta| meta.release_id.as_deref())
                .is_some_and(|installed| installed == actual);
            if materialized {
                info!("installation {subject} already has {actual} materialized");
                // A paused installation keeps its files, so resuming it finds
                // them materialized and has only to put the extender back.
                register_installed_plugin(
                    store,
                    drive,
                    &namespace,
                    &name,
                    plugins_dir,
                    plugin_cache_dir,
                )
                .await?;
            } else {
                let package = release
                    .package
                    .as_deref()
                    .ok_or("a wasip2 release without a package")?;
                let bytes = release::package_bytes(store, package).await?;
                let mut zip = ZipArchive::new(std::io::Cursor::new(bytes))
                    .map_err(|e| AtomicError::from(format!("package is not a zip archive: {e}")))?;
                // A release published before manifests were unified carries
                // its `plugin.json`; the package itself says what it translates to.
                let manifest = match Manifest::parse(release.manifest.clone()) {
                    Ok(Some(manifest)) => manifest,
                    Ok(None) => describe_package(store, &mut zip).await?,
                    Err(e) => {
                        return Err(AtomicError::from(format!(
                            "release manifest is invalid: {e}"
                        )))
                    }
                };
                install_or_update_plugin(
                    &mut zip,
                    drive,
                    &subject,
                    &manifest,
                    store,
                    plugins_dir,
                    plugin_cache_dir,
                )
                .await?;
                // Now that this release's code is the code on disk, say so, so
                // the next activation can tell. Written after the install
                // rather than by it: a failed extraction leaves no id, and no
                // id means materialize again.
                record_materialized_release(store, &key, &actual)?;
            }
        } else {
            ensure_js_identity(store, drive, &subject, &namespace, &name, &release, &actual)
                .await?;
        }
        info!(
            "activated installation {subject} ({namespace}/{name}, {})",
            release.runtime
        );
        Ok(())
    }

    /// A JS installation writes nothing to disk. Its identity is the app
    /// agent `installation::resolve` looks up, mirrored into `PluginMeta` so
    /// both runtimes are listed in one place.
    async fn ensure_js_identity(
        store: &Db,
        drive: &str,
        subject: &str,
        namespace: &str,
        name: &str,
        release: &PluginRelease,
        release_id: &str,
    ) -> AtomicResult<()> {
        let app_key = AppAgentKey::new(drive, subject);
        let secret = match store.get_app_agent_state(&app_key)? {
            AppAgentState::Revoked => {
                return Err(AtomicError::from(
                    "this installation's identity was revoked; create a new Installation",
                ))
            }
            AppAgentState::Active(_) => store
                .with_app_agent(&app_key, |agent| agent.build_secret())?
                .ok_or("installation identity vanished")??,
            AppAgentState::Legacy => {
                let agent = Agent::new(Some(name))?;
                let mut agent_resource = agent.to_resource()?;
                agent_resource
                    .set(
                        urls::NAME.into(),
                        Value::String(format!("{namespace}/{name}")),
                        store,
                    )
                    .await?;
                agent_resource.save_locally(store).await?;
                let secret = agent.build_secret()?;
                store.set_app_agent(
                    &app_key,
                    &AppAgent::new(
                        agent.subject.to_string(),
                        secret.clone(),
                        atomic_lib::utils::now(),
                    ),
                )?;
                secret
            }
        };
        store.set_plugin_meta(
            &PluginMetaKey::new(drive, namespace, name),
            &PluginMeta {
                subject: subject.to_string(),
                agent_secret: secret,
                manifest: release.manifest.clone(),
                release_id: Some(release_id.to_string()),
            },
        )?;
        Ok(())
    }

    /// Stop a plugin without uninstalling it.
    ///
    /// `paused` and `draft` both mean "installed, not running". For a wasip2
    /// class extender that is an unregistration: the hooks stop firing on the
    /// next commit, while the files and `PluginMeta` stay, so resuming keeps
    /// the plugin's agent rather than minting a new one. A JS installation has
    /// no extender to unregister; its runs are refused by
    /// `installation::resolve`, which reads the status.
    pub async fn suspend(resource: &Resource, drive: &str, store: &Db) -> AtomicResult<()> {
        let subject = resource.get_subject().to_string();
        let Some((namespace, name)) = identifiers_of_installed(resource, store) else {
            return Ok(());
        };
        let key = PluginMetaKey::new(drive, &namespace, &name);
        // Only this installation's own extender, never one that happens to
        // share a namespace and name.
        if store
            .get_plugin_meta(&key)?
            .is_some_and(|meta| meta.subject == subject)
        {
            suspend_plugin(store, drive, &namespace, &name)?;
            info!("suspended installation {subject}");
        }
        Ok(())
    }

    /// Undo an activation. Best effort on every step, so a half-installed
    /// plugin can still be revoked or destroyed.
    pub async fn deactivate(
        resource: &Resource,
        drive: &str,
        store: &Db,
        plugins_dir: &Path,
    ) -> AtomicResult<()> {
        let subject = resource.get_subject().to_string();
        // Identifiers live on the resource, or in the manifest of the pinned
        // release, which is in this node's cache once it was ever activated.
        let identifiers = identifiers_of_installed(resource, store);
        if let Some((namespace, name)) = identifiers {
            let key = PluginMetaKey::new(drive, &namespace, &name);
            if let Some(meta) = store.get_plugin_meta(&key)? {
                if meta.subject == subject {
                    // The wasm path removes the files and the meta; a JS
                    // installation has no files, so only the meta is left.
                    if let Err(e) =
                        uninstall_plugin(&name, &namespace, drive, store, plugins_dir).await
                    {
                        tracing::debug!("no wasm files to remove for {subject}: {e}");
                    }
                    store.delete_plugin_meta(&key)?;
                }
            }
        }
        let app_key = AppAgentKey::new(drive, &subject);
        if let AppAgentState::Active(_) = store.get_app_agent_state(&app_key)? {
            // Leaves the revocation tombstone `installation::resolve` honours.
            store.delete_app_agent(&app_key)?;
        }
        info!("deactivated installation {subject}");
        Ok(())
    }

    pub fn status(resource: &Resource) -> String {
        string_value(resource, urls::INSTALLATION_STATUS).unwrap_or_else(|| STATUS_DRAFT.into())
    }

    /// Records which release's code is now on disk for this plugin.
    fn record_materialized_release(
        store: &Db,
        key: &PluginMetaKey,
        release_id: &str,
    ) -> AtomicResult<()> {
        let Some(meta) = store.get_plugin_meta(key)? else {
            return Err(AtomicError::from(
                "the install wrote no plugin metadata to record a release on",
            ));
        };
        store.set_plugin_meta(
            key,
            &PluginMeta {
                release_id: Some(release_id.to_string()),
                ..meta
            },
        )
    }

    /// The namespace and name a materialized installation was installed under.
    ///
    /// They live on the resource, or in the manifest of the pinned release,
    /// which is in this node's cache once it was ever activated.
    fn identifiers_of_installed(resource: &Resource, store: &Db) -> Option<(String, String)> {
        match get_namespace_and_name(resource) {
            Ok(found) => Some(found),
            Err(_) => {
                let id = string_value(resource, urls::RELEASE_ID)?;
                let release = store.get_plugin_release(&id).ok()?;
                identifiers(resource, &release.manifest).ok()
            }
        }
    }
}

#[allow(unused_variables)]
fn on_installation_before_commit(
    context: CommitExtenderContext,
    plugins_dir: PathBuf,
    plugin_cache_dir: PathBuf,
) -> BoxFuture<AtomicResult<()>> {
    Box::pin(async move {
        let CommitExtenderContext {
            store,
            commit,
            resource,
            is_new,
            changed_props,
        } = context;

        let drive = get_parent_drive(resource, store).await?;

        if commit.destroy == Some(true) {
            #[cfg(feature = "wasm-plugins")]
            installation_hook::deactivate(resource, &drive, store, &plugins_dir).await?;
            return Ok(());
        }

        if !is_new {
            for prop in [urls::NAME, urls::NAMESPACE, urls::PARENT] {
                if changed_props.contains(prop) {
                    return Err(AtomicError::from(
                        "Cannot change an Installation's name, namespace or parent after it was created",
                    ));
                }
            }
        }

        #[cfg(feature = "wasm-plugins")]
        {
            use installation_hook::*;
            let status = status(resource);
            let activation_changed = is_new
                || [
                    urls::INSTALLATION_STATUS,
                    urls::RELEASE_PROP,
                    urls::RELEASE_ID,
                    urls::GRANTS,
                    urls::CONFIG,
                ]
                .iter()
                .any(|prop| changed_props.contains(*prop));
            match status.as_str() {
                STATUS_ACTIVE if activation_changed => {
                    activate(
                        resource,
                        &drive,
                        store,
                        commit.signer.as_str(),
                        &plugins_dir,
                        &plugin_cache_dir,
                    )
                    .await?
                }
                STATUS_ACTIVE => {}
                STATUS_REVOKED if changed_props.contains(urls::INSTALLATION_STATUS) => {
                    deactivate(resource, &drive, store, &plugins_dir).await?
                }
                // Installed but not running. Unlike `revoked` this keeps the
                // files and the identity, so it is an unregistration, not an
                // uninstall. `is_new` cannot have been running.
                STATUS_PAUSED | STATUS_DRAFT
                    if !is_new && changed_props.contains(urls::INSTALLATION_STATUS) =>
                {
                    suspend(resource, &drive, store).await?
                }
                STATUS_REVOKED | STATUS_DRAFT | STATUS_PAUSED => {}
                other => {
                    return Err(AtomicError::from(format!(
                        "unknown installationStatus '{other}'; expected draft, active, paused or revoked"
                    )))
                }
            }
        }

        Ok(())
    })
}

pub fn build_installation_extender(
    plugins_dir: PathBuf,
    plugin_cache_dir: PathBuf,
) -> ClassExtender {
    ClassExtender::builder()
        .id("installation".to_string())
        .classes(vec![urls::INSTALLATION.to_string()])
        .on_resource_get(ClassExtender::wrap_get_handler(move |context| {
            on_resource_get(context)
        }))
        .before_commit(ClassExtender::wrap_commit_handler(move |context| {
            on_installation_before_commit(context, plugins_dir.clone(), plugin_cache_dir.clone())
        }))
        .build()
}

// ---------------------------------------------------------------------------
// Legacy `Plugin` resources
// ---------------------------------------------------------------------------

/// Rewrites every legacy `Plugin` + `pluginFile` resource on this node as an
/// `Installation`, once.
///
/// For each one: the zip its `pluginFile` points at is published as a Release
/// (content-addressed, so a second run finds the same id) and recorded at
/// `<server>/releases/<id>`; the resource then becomes an Installation pinned
/// to that release, with `grants` equal to the manifest's capabilities, its
/// `config` untouched and `installationStatus: active`. The subject does not
/// change, and neither do the files on disk: the plugin's meta already holds
/// this exact manifest, so the Installation hook sees the release as
/// materialized and does not extract or compile anything again.
///
/// Signed by the server's agent. Returns how many resources were migrated;
/// a resource that cannot be migrated is logged and left as it is.
#[cfg(feature = "wasm-plugins")]
pub async fn migrate_legacy_plugins(store: &Db) -> AtomicResult<usize> {
    use atomic_lib::storelike::Query;

    let legacy = store
        .query(&Query {
            property: Some(urls::IS_A.into()),
            value: Some(Value::AtomicUrl(urls::PLUGIN.into())),
            include_nested: true,
            for_agent: ForAgent::Sudo,
            ..Default::default()
        })
        .await?;
    let mut migrated = 0;
    for resource in legacy.resources {
        let subject = resource.get_subject().to_string();
        match migrate_legacy_plugin(store, resource).await {
            Ok(true) => migrated += 1,
            Ok(false) => {}
            Err(e) => tracing::warn!("could not migrate legacy plugin {subject}: {e}"),
        }
    }
    if migrated > 0 {
        tracing::info!("migrated {migrated} legacy Plugin resource(s) to Installations");
    }
    Ok(migrated)
}

#[cfg(feature = "wasm-plugins")]
async fn migrate_legacy_plugin(store: &Db, mut resource: Resource) -> AtomicResult<bool> {
    use crate::plugins::release;
    use atomic_lib::db::plugin_meta::PluginMeta;

    let subject = resource.get_subject().to_string();
    let Some(plugin_file) = string_value(&resource, urls::PLUGIN_FILE) else {
        tracing::warn!("legacy plugin {subject} has no pluginFile; nothing to migrate it to");
        return Ok(false);
    };
    let drive = get_parent_drive(&resource, store).await?;
    let bytes = release::file_bytes(store, &plugin_file).await?;
    // No claimed world: the zip is already installed, so its own component
    // decides what it is.
    let (id, published, manifest) = release::publish_package(store, &bytes, None).await?;
    let origin = store.get_server_url();
    let release_url = release::record_release(store, &id, &published, &drive, None, &origin)
        .await?
        .resolve(&origin);

    // The plugin's meta is what the loader wrote from its `plugin.json`; give
    // it the manifest the release carries, which is that same `plugin.json`
    // translated, so activation finds the release already materialized.
    let (namespace, name) = installation_hook::identifiers(&resource, &published.manifest)?;
    let key = PluginMetaKey::new(&drive, &namespace, &name);
    if let Some(meta) = store.get_plugin_meta(&key)? {
        if meta.subject == subject
            && (meta.manifest != published.manifest
                || meta.release_id.as_deref() != Some(id.as_str()))
        {
            store.set_plugin_meta(
                &key,
                &PluginMeta {
                    manifest: published.manifest.clone(),
                    release_id: Some(id.clone()),
                    ..meta
                },
            )?;
        }
    }

    let grants: Vec<&str> = manifest
        .capabilities
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    resource.set_unsafe(
        urls::IS_A.into(),
        Value::ResourceArray(vec![urls::INSTALLATION.into()]),
    )?;
    resource.set_unsafe(
        urls::RELEASE_PROP.into(),
        Value::AtomicUrl(release_url.into()),
    )?;
    resource.set_unsafe(urls::RELEASE_ID.into(), Value::String(id.clone()))?;
    resource.set_unsafe(urls::GRANTS.into(), Value::Json(serde_json::json!(grants)))?;
    resource.set_unsafe(
        urls::INSTALLATION_STATUS.into(),
        Value::String(STATUS_ACTIVE.into()),
    )?;
    resource.remove_propval(urls::PLUGIN_FILE)?;
    resource.save_locally(store).await?;
    tracing::info!("migrated legacy plugin {subject} to an Installation of {id}");
    Ok(true)
}

#[cfg(all(test, feature = "wasm-plugins"))]
mod installation_tests {
    use super::*;
    use crate::plugins::{
        host_core::{installation_grants, ResourceGrants},
        installation,
        manifest::Manifest,
        release,
        test_fixture::{fixture, genesis},
        wasm,
    };
    use atomic_lib::db::{
        app_agent::AppAgentKey,
        plugin_meta::PluginMeta,
        plugin_release::{PluginRelease, RUNTIME_WASIP2, WORLD_EXTENSION, WORLD_SERVER_EXTENSION},
    };
    use serde_json::json;

    const TEST_PLUGIN_ZIP: &[u8] =
        include_bytes!("../../../browser/e2e/tests/fixtures/test-plugin.zip");

    fn js_release(world: &str) -> PluginRelease {
        let mut release = PluginRelease::js(
            "export function run() { return { intents: [] }; }".into(),
            json!({"schemaVersion":2,"capabilities":[{"name":"storage","reason":"keeps a cursor"}]}),
            Default::default(),
        );
        release.world = world.into();
        release
    }

    fn installation_props<'a>(
        drive: &'a str,
        namespace: &'a str,
        name: &'a str,
        release: &'a str,
        pinned: &'a str,
        status: &'a str,
    ) -> Vec<(&'a str, Value)> {
        vec![
            (
                urls::IS_A,
                Value::ResourceArray(vec![urls::INSTALLATION.into()]),
            ),
            (urls::PARENT, Value::AtomicUrl(drive.into())),
            (urls::NAME, Value::String(name.into())),
            (urls::NAMESPACE, Value::String(namespace.into())),
            (urls::RELEASE_PROP, Value::String(release.into())),
            (urls::RELEASE_ID, Value::String(pinned.into())),
            (urls::INSTALLATION_STATUS, Value::String(status.into())),
            (urls::GRANTS, Value::Json(json!(["storage"]))),
        ]
    }

    /// Like `genesis`, but returns the commit error instead of panicking.
    async fn try_genesis(store: &Db, propvals: Vec<(&str, Value)>) -> AtomicResult<String> {
        let mut resource = Resource::new("did:ad:placeholder".into());
        for (property, value) in propvals {
            resource.set_unsafe(property.into(), value)?;
        }
        resource.save_as_genesis(store).await?;
        Ok(resource.get_subject().to_string())
    }

    async fn set_status(db: &Db, subject: &str, status: &str) {
        let mut r = db.get_resource(&subject.into()).await.unwrap();
        r.set_unsafe(
            urls::INSTALLATION_STATUS.into(),
            Value::String(status.into()),
        )
        .unwrap();
        r.save(db).await.unwrap();
    }

    #[actix_rt::test]
    async fn an_active_js_installation_mints_its_identity_and_revocation_tombstones_it() {
        let f = fixture("installation_js").await;
        let db = &f.appstate.store;
        let id = db
            .publish_plugin_release(&js_release(WORLD_EXTENSION))
            .unwrap();
        let installation = genesis(
            db,
            installation_props(&f.drive, "acme", "importer", &id, &id, "active"),
        )
        .await;

        let key = PluginMetaKey::new(&f.drive, "acme", "importer");
        let meta = db
            .get_plugin_meta(&key)
            .unwrap()
            .expect("a PluginMeta record");
        assert_eq!(meta.subject, installation);
        assert_eq!(meta.manifest, js_release(WORLD_EXTENSION).manifest);
        let app_key = AppAgentKey::new(&f.drive, &installation);
        assert_eq!(
            installation::resolve(db, &f.drive, &installation)
                .await
                .unwrap()
                .signing_as,
            Some(app_key.clone())
        );
        let agent = db.get_app_agent_info(&app_key).unwrap().unwrap().agent;
        assert_eq!(
            Agent::from_secret(&meta.agent_secret)
                .unwrap()
                .subject
                .to_string(),
            agent
        );

        // The same identifiers cannot be claimed by a second installation.
        let clash = try_genesis(
            db,
            installation_props(&f.drive, "acme", "importer", &id, &id, "active"),
        )
        .await
        .unwrap_err();
        assert!(clash.to_string().contains("already installed"), "{clash}");

        set_status(db, &installation, "revoked").await;
        assert!(db.get_plugin_meta(&key).unwrap().is_none());
        let err = installation::resolve(db, &f.drive, &installation)
            .await
            .err()
            .expect("a revoked identity no longer resolves");
        assert!(err.contains("revoked"), "{err}");
        assert!(db.app_agent_was_revoked(&app_key).unwrap());
    }

    /// A run belongs to an Installation, so it is limited to the grants the
    /// installer approved. Falling back to the manifest's own declared set
    /// would hand a plugin what it asked for rather than what it was given,
    /// and that is the one direction a fallback must never take.
    ///
    /// Reading the Installation's classes is the other half, and that is a unit
    /// test on `Resource::class_subjects` instead: the encodings which used to
    /// defeat the class check come from rebuilt rows, and a store write
    /// normalizes them away, so there is no way to write one here.
    #[actix_rt::test]
    async fn a_js_run_gets_the_approved_grants_rather_than_the_declared_ones() {
        let f = fixture("installation_grants").await;
        let db = &f.appstate.store;
        // Only the two budget capabilities show up in `ResourceGrants`, so the
        // release declares one of them and the Installation approves that one.
        let mut release = PluginRelease::js(
            "export function run() { return { intents: [] }; }".into(),
            json!({
                "schemaVersion": 2,
                "capabilities": [{"name": "extended-fuel", "reason": "long imports"}]
            }),
            Default::default(),
        );
        release.world = WORLD_EXTENSION.into();
        let id = db.publish_plugin_release(&release).unwrap();
        let mut props = installation_props(&f.drive, "acme", "importer", &id, &id, "active");
        props.retain(|(prop, _)| *prop != urls::GRANTS);
        props.push((urls::GRANTS, Value::Json(json!(["extended-fuel"]))));
        let installation = genesis(db, props).await;

        // The manifest the run carries asks for both budgets; the Installation
        // approved one. `check_grants` makes the sets equal at install time, so
        // this is the drift an Installation written before that rule carries.
        let manifest = Manifest::parse(json!({
            "schemaVersion": 2,
            "capabilities": [
                {"name": "extended-fuel", "reason": "long imports"},
                {"name": "extended-memory", "reason": "big documents"}
            ]
        }))
        .unwrap()
        .expect("a version-two manifest");
        let approved = ResourceGrants::from_grants(&json!(["extended-fuel"]));
        let declared = ResourceGrants::from_v2(Some(&manifest));
        assert_ne!(approved, declared, "the test needs the two to differ");

        let granted = installation_grants(db, &f.drive, &installation, Some(&manifest)).await;
        assert_eq!(granted, approved, "the approved set is what runs");
    }

    #[actix_rt::test]
    async fn a_tampered_or_server_extension_release_is_refused() {
        let f = fixture("installation_refused").await;
        let db = &f.appstate.store;
        let id = db
            .publish_plugin_release(&js_release(WORLD_EXTENSION))
            .unwrap();

        let forged = format!("blake3:{}", "0".repeat(64));
        let err = try_genesis(
            db,
            installation_props(&f.drive, "acme", "forged", &id, &forged, "active"),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("refusing to install"), "{err}");
        assert!(db
            .get_plugin_meta(&PluginMetaKey::new(&f.drive, "acme", "forged"))
            .unwrap()
            .is_none());

        let server_only = db
            .publish_plugin_release(&js_release(WORLD_SERVER_EXTENSION))
            .unwrap();
        let err = try_genesis(
            db,
            installation_props(
                &f.drive,
                "acme",
                "hooks",
                &server_only,
                &server_only,
                "active",
            ),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("server-extension"), "{err}");

        let mut greedy = installation_props(&f.drive, "acme", "greedy", &id, &id, "active");
        greedy.retain(|(prop, _)| *prop != urls::GRANTS);
        greedy.push((urls::GRANTS, Value::Json(json!(["full-drive-access"]))));
        let err = try_genesis(db, greedy).await.unwrap_err();
        assert!(err.to_string().contains("not declared"), "{err}");

        // Granting less than the manifest declares is refused too, naming the
        // capability and its reason.
        let mut stingy = installation_props(&f.drive, "acme", "stingy", &id, &id, "active");
        stingy.retain(|(prop, _)| *prop != urls::GRANTS);
        stingy.push((urls::GRANTS, Value::Json(json!([]))));
        let err = try_genesis(db, stingy).await.unwrap_err();
        assert!(
            err.to_string().contains("storage (keeps a cursor)"),
            "{err}"
        );

        // A draft does nothing, and can be created for any release.
        let draft = genesis(
            db,
            installation_props(&f.drive, "acme", "later", &id, &forged, "draft"),
        )
        .await;
        assert!(db.get_resource(&draft.as_str().into()).await.is_ok());
    }

    /// The capabilities `test-plugin.zip` declares in its `plugin.json`.
    const TEST_PLUGIN_GRANTS: [&str; 3] = ["storage", "custom-view", "full-drive-access"];

    #[actix_rt::test]
    async fn a_wasip2_release_carries_a_v2_manifest_read_from_the_component() {
        let f = fixture("wasm_release_manifest").await;
        let db = &f.appstate.store;
        let (id, release, manifest) = release::publish_package(db, TEST_PLUGIN_ZIP, None)
            .await
            .unwrap();
        assert_eq!(release.runtime, RUNTIME_WASIP2);
        assert_eq!(release.package.as_deref().map(str::len), Some(64));
        assert_eq!(release.version.as_deref(), Some("1.0.0"));
        // The component extends Folder (and a test class), so the package is
        // a server-extension with those classes as its entrypoints.
        assert_eq!(release.world, WORLD_SERVER_EXTENSION);
        let classes = manifest.entrypoints.class_urls();
        assert_eq!(classes.len(), 2, "{classes:?}");
        assert!(
            classes.contains(&"https://atomicdata.dev/classes/Folder".to_string()),
            "{classes:?}"
        );
        assert!(!manifest.entrypoints.run);
        assert_eq!(release.manifest["schemaVersion"], 2);
        assert_eq!(release.manifest["runtime"], "wasip2/1");
        assert_eq!(release.manifest["world"], "server-extension");
        assert_eq!(release.manifest["namespace"], "ontola");
        assert_eq!(release.manifest["name"], "test-plugin");
        let declared: Vec<&str> = manifest
            .capabilities
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(declared, TEST_PLUGIN_GRANTS);
        assert!(manifest.capabilities.iter().all(|c| c.reason.is_some()));
        // The stored manifest parses back as the same version-two manifest.
        crate::plugins::manifest::Manifest::parse(release.manifest.clone())
            .unwrap()
            .unwrap();
        // Content-addressed: the same bytes publish to the same id.
        let (again, _, _) = release::publish_package(db, TEST_PLUGIN_ZIP, None)
            .await
            .unwrap();
        assert_eq!(again, id);
        assert_eq!(db.get_plugin_release(&id).unwrap(), release);
    }

    #[actix_rt::test]
    async fn a_wasip2_installation_goes_through_the_zip_install_path() {
        let f = fixture("installation_wasm").await;
        let db = &f.appstate.store;
        let (id, release, _) = release::publish_package(db, TEST_PLUGIN_ZIP, None)
            .await
            .unwrap();

        // Grants must cover every capability the package declares.
        let mut props = installation_props(&f.drive, "ontola", "test-plugin", &id, &id, "active");
        props.retain(|(prop, _)| *prop != urls::GRANTS);
        props.push((urls::GRANTS, Value::Json(json!(["storage", "custom-view"]))));
        let err = try_genesis(db, props).await.unwrap_err();
        assert!(err.to_string().contains("full-drive-access ("), "{err}");
        let key = PluginMetaKey::new(&f.drive, "ontola", "test-plugin");
        assert!(db.get_plugin_meta(&key).unwrap().is_none());

        // Identifiers on the resource must agree with the package.
        let mut props = installation_props(&f.drive, "ontola", "renamed", &id, &id, "active");
        props.retain(|(prop, _)| *prop != urls::GRANTS);
        props.push((urls::GRANTS, Value::Json(json!(TEST_PLUGIN_GRANTS))));
        let err = try_genesis(db, props).await.unwrap_err();
        assert!(err.to_string().contains("differs from"), "{err}");

        // A draft installs nothing; activating it in a second commit does.
        let mut props = installation_props(&f.drive, "ontola", "test-plugin", &id, &id, "draft");
        props.retain(|(prop, _)| *prop != urls::GRANTS);
        props.push((urls::GRANTS, Value::Json(json!(TEST_PLUGIN_GRANTS))));
        let installation = genesis(db, props).await;
        assert!(db.get_plugin_meta(&key).unwrap().is_none());
        assert!(db.get_class_extenders_on_drive(&f.drive).is_empty());

        set_status(db, &installation, "active").await;

        let meta = db.get_plugin_meta(&key).unwrap().expect("installed");
        assert_eq!(meta.subject, installation);
        assert_eq!(meta.version(), Some("1.0.0"));
        assert_eq!(meta.manifest, release.manifest);
        // Drive-scoped: the class extender is registered on this drive only
        // (`get_class_extenders_on_drive` filters on `ClassExtenderScope::Drive`).
        assert_eq!(db.get_class_extenders_on_drive(&f.drive).len(), 1);
        // The dynamic properties are served for an Installation.
        let shown = db
            .get_resource_extended(&installation.as_str().into(), false, &ForAgent::Sudo)
            .await
            .unwrap()
            .to_single();
        assert!(shown.get(urls::PLUGIN_AGENT).is_ok());
        assert_eq!(shown.get(urls::VERSION).unwrap().to_string(), "1.0.0");
        let permissions = shown.get(urls::PLUGIN_PERMISSIONS).unwrap().to_string();
        assert!(permissions.contains("full-drive-access"), "{permissions}");

        assert_eq!(meta.release_id.as_deref(), Some(id.as_str()));

        // Pausing stops the plugin without uninstalling it: the extender is
        // gone, the files and the identity stay, so resuming is the same agent.
        let wasm_file = f
            .appstate
            .config
            .plugin_path
            .join("class-extenders/scoped")
            .join(base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE,
                &f.drive,
            ))
            .join("ontola.test-plugin.wasm");
        let before = std::fs::metadata(&wasm_file).unwrap().modified().unwrap();
        let agent_before = db.get_plugin_meta(&key).unwrap().unwrap().agent_secret;

        set_status(db, &installation, "paused").await;
        assert!(
            db.get_class_extenders_on_drive(&f.drive).is_empty(),
            "a paused installation must not keep serving its hooks"
        );
        assert!(wasm_file.exists(), "pausing is not an uninstall");
        assert!(db.get_plugin_meta(&key).unwrap().is_some());

        set_status(db, &installation, "active").await;
        assert_eq!(db.get_class_extenders_on_drive(&f.drive).len(), 1);
        assert_eq!(
            db.get_plugin_meta(&key).unwrap().unwrap().agent_secret,
            agent_before,
            "resuming must keep the plugin's identity"
        );
        assert_eq!(
            std::fs::metadata(&wasm_file).unwrap().modified().unwrap(),
            before,
            "re-activating the same release must not re-extract"
        );

        // A config change on a running plugin re-activates it and likewise
        // extracts nothing, since the release on disk is the one pinned.
        let mut r = db
            .get_resource(&installation.as_str().into())
            .await
            .unwrap();
        r.set(
            urls::CONFIG.into(),
            Value::Json(json!({"greeting": "hoi"})),
            db,
        )
        .await
        .unwrap();
        r.save(db).await.unwrap();
        assert_eq!(
            std::fs::metadata(&wasm_file).unwrap().modified().unwrap(),
            before,
            "a config change must not re-extract"
        );
        assert_eq!(db.get_class_extenders_on_drive(&f.drive).len(), 1);

        let mut r = db
            .get_resource(&installation.as_str().into())
            .await
            .unwrap();
        r.destroy(db).await.unwrap();
        assert!(db.get_plugin_meta(&key).unwrap().is_none());
        assert!(!wasm_file.exists());
    }

    /// The same plugin, repackaged: every entry byte-for-byte identical, only
    /// the archive's own framing different. So the two releases have the same
    /// manifest and different package bytes, which is exactly the pair an
    /// install must be able to tell apart.
    fn repackaged(bytes: &[u8]) -> Vec<u8> {
        let mut source = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).unwrap();
        let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for i in 0..source.len() {
            let mut entry = source.by_index(i).unwrap();
            let name = entry.name().to_string();
            if name.ends_with('/') {
                out.add_directory(name, options).unwrap();
                continue;
            }
            let mut content = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut content).unwrap();
            out.start_file(name, options).unwrap();
            std::io::Write::write_all(&mut out, &content).unwrap();
        }
        out.finish().unwrap().into_inner()
    }

    /// Two releases of one plugin can agree on every manifest field and differ
    /// in their code. Repointing an Installation at the second one has to put
    /// the new code on disk; the manifest cannot be what decides that.
    #[actix_rt::test]
    async fn a_new_release_with_an_unchanged_manifest_still_replaces_the_code() {
        let f = fixture("installation_same_manifest").await;
        let db = &f.appstate.store;
        let (first, first_release, _) = release::publish_package(db, TEST_PLUGIN_ZIP, None)
            .await
            .unwrap();
        let (second, second_release, _) =
            release::publish_package(db, &repackaged(TEST_PLUGIN_ZIP), None)
                .await
                .unwrap();

        assert_ne!(first, second, "different bytes are a different release");
        assert_eq!(
            first_release.manifest, second_release.manifest,
            "the fixture is only useful if the manifests match"
        );
        assert_ne!(first_release.package, second_release.package);

        let mut props =
            installation_props(&f.drive, "ontola", "test-plugin", &first, &first, "active");
        props.retain(|(prop, _)| *prop != urls::GRANTS);
        props.push((urls::GRANTS, Value::Json(json!(TEST_PLUGIN_GRANTS))));
        let installation = genesis(db, props).await;

        let key = PluginMetaKey::new(&f.drive, "ontola", "test-plugin");
        assert_eq!(
            db.get_plugin_meta(&key).unwrap().unwrap().release_id,
            Some(first.clone())
        );

        // Repoint it at the second release, both properties in one commit.
        let mut r = db
            .get_resource(&installation.as_str().into())
            .await
            .unwrap();
        // A bare id in `release`: the form Installations written before every
        // publish recorded a `Release` resource carry, which still resolves.
        r.set_unsafe(urls::RELEASE_PROP.into(), Value::String(second.clone()))
            .unwrap();
        r.set_unsafe(urls::RELEASE_ID.into(), Value::String(second.clone()))
            .unwrap();
        r.save(db).await.unwrap();

        assert_eq!(
            db.get_plugin_meta(&key).unwrap().unwrap().release_id,
            Some(second),
            "the installation must record the release whose code is on disk"
        );
        assert_eq!(db.get_class_extenders_on_drive(&f.drive).len(), 1);
    }

    #[actix_rt::test]
    async fn a_package_that_is_not_on_this_node_cannot_be_installed() {
        let f = fixture("installation_missing_package").await;
        let db = &f.appstate.store;
        let id = db
            .publish_plugin_release(&PluginRelease {
                source: None,
                package: Some("ab".repeat(32)),
                manifest: json!({"name":"ghost","namespace":"acme","version":"0.1.0"}),
                runtime: RUNTIME_WASIP2.into(),
                world: WORLD_EXTENSION.into(),
                schemas: Default::default(),
                version: None,
                previous_release: None,
            })
            .unwrap();
        // A legacy plugin.json manifest without permissions declares nothing.
        let mut props = installation_props(&f.drive, "acme", "ghost", &id, &id, "active");
        props.retain(|(prop, _)| *prop != urls::GRANTS);
        let err = try_genesis(db, props).await.unwrap_err();
        assert!(err.to_string().contains("not on this node"), "{err}");
    }

    #[actix_rt::test]
    async fn an_installation_can_pin_a_release_by_its_resource_url() {
        let f = fixture("installation_release_url").await;
        let db = &f.appstate.store;
        let origin = db.get_server_url();
        let (id, published, _) = release::publish_package(db, TEST_PLUGIN_ZIP, None)
            .await
            .unwrap();
        let subject = release::record_release(db, &id, &published, &f.drive, None, &origin)
            .await
            .unwrap();
        let url = subject.resolve(&origin);
        assert!(url.ends_with(&format!("/releases/{id}")), "{url}");
        // Recording twice is a no-op, and the resource round-trips the release.
        assert_eq!(
            release::record_release(db, &id, &published, &f.drive, None, &origin)
                .await
                .unwrap(),
            subject
        );
        let resource = db.get_resource(&subject).await.unwrap();
        assert_eq!(
            resource.get(urls::RELEASE_ID).unwrap().to_string(),
            id,
            "the resource records the id"
        );
        let file = resource.get(urls::PACKAGE).unwrap().to_string();
        let file = db.get_resource(&file.as_str().into()).await.unwrap();
        assert_eq!(
            file.get(urls::INTERNAL_ID).unwrap().to_string(),
            published.package.clone().unwrap()
        );
        // The URL resolves to the same release as the bare id.
        let signer = ForAgent::AgentSubject(db.get_default_agent().unwrap().subject);
        let resolved = release::resolve(db, &url, &signer).await.unwrap();
        assert_eq!(resolved, published);
        assert_eq!(resolved.id().unwrap(), id);

        // And an Installation can point at it instead of the bare id.
        let mut props = installation_props(&f.drive, "ontola", "test-plugin", &url, &id, "draft");
        props.retain(|(prop, _)| *prop != urls::GRANTS);
        props.push((urls::GRANTS, Value::Json(json!(TEST_PLUGIN_GRANTS))));
        let installation = genesis(db, props).await;
        set_status(db, &installation, "active").await;
        let key = PluginMetaKey::new(&f.drive, "ontola", "test-plugin");
        let meta = db.get_plugin_meta(&key).unwrap().expect("installed by URL");
        assert_eq!(meta.subject, installation);
        assert_eq!(meta.manifest, published.manifest);

        // A JS release records without a File.
        let js = js_release(WORLD_EXTENSION);
        let js_id = db.publish_plugin_release(&js).unwrap();
        let js_subject = release::record_release(db, &js_id, &js, &f.drive, None, &origin)
            .await
            .unwrap();
        let js_url = js_subject.resolve(&origin);
        assert_eq!(release::resolve(db, &js_url, &signer).await.unwrap(), js);
    }

    /// A drive with a plugin installed the way the legacy `Plugin` +
    /// `pluginFile` hook did it: a File holding the zip, a `Plugin` resource
    /// pointing at it, the package extracted and loaded, and a meta record
    /// holding the untranslated `plugin.json`.
    async fn legacy_plugin(f: &crate::plugins::test_fixture::Fixture) -> (String, PathBuf) {
        let db = &f.appstate.store;
        let package = release::store_package(db, TEST_PLUGIN_ZIP).await.unwrap();
        let file = genesis(
            db,
            vec![
                (urls::IS_A, Value::ResourceArray(vec![urls::FILE.into()])),
                (urls::PARENT, Value::AtomicUrl(f.drive.as_str().into())),
                (urls::INTERNAL_ID, Value::String(package.clone())),
                (urls::MIMETYPE, Value::String("application/zip".into())),
                (urls::FILENAME, Value::String("test-plugin.zip".into())),
                (
                    urls::DOWNLOAD_URL,
                    Value::String(format!("{}/download/files/{package}", db.get_server_url())),
                ),
            ],
        )
        .await;
        let plugin = genesis(
            db,
            vec![
                (urls::IS_A, Value::ResourceArray(vec![urls::PLUGIN.into()])),
                (urls::PARENT, Value::AtomicUrl(f.drive.as_str().into())),
                (urls::NAME, Value::String("test-plugin".into())),
                (urls::NAMESPACE, Value::String("ontola".into())),
                (urls::VERSION, Value::String("1.0.0".into())),
                (urls::PLUGIN_FILE, Value::AtomicUrl(file.as_str().into())),
                (urls::CONFIG, Value::Json(json!({"greeting": "hi"}))),
            ],
        )
        .await;
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(TEST_PLUGIN_ZIP.to_vec())).unwrap();
        let manifest = wasm::describe_package(db, &mut zip).await.unwrap();
        wasm::install_or_update_plugin(
            &mut zip,
            &f.drive,
            &plugin,
            &manifest,
            db,
            &f.appstate.config.plugin_path,
            &f.appstate.config.plugin_cache_path,
        )
        .await
        .unwrap();
        // The legacy loader kept the `plugin.json` itself.
        let key = PluginMetaKey::new(&f.drive, "ontola", "test-plugin");
        let meta = db.get_plugin_meta(&key).unwrap().unwrap();
        let plugin_json: serde_json::Value = serde_json::from_reader(
            zip::ZipArchive::new(std::io::Cursor::new(TEST_PLUGIN_ZIP.to_vec()))
                .unwrap()
                .by_name("plugin.json")
                .unwrap(),
        )
        .unwrap();
        db.set_plugin_meta(
            &key,
            &PluginMeta {
                manifest: plugin_json,
                ..meta
            },
        )
        .unwrap();
        let wasm_file = f
            .appstate
            .config
            .plugin_path
            .join("class-extenders/scoped")
            .join(base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE,
                &f.drive,
            ))
            .join("ontola.test-plugin.wasm");
        assert!(wasm_file.exists());
        (plugin, wasm_file)
    }

    #[actix_rt::test]
    async fn a_legacy_plugin_is_migrated_once_into_an_installation_without_reinstalling() {
        let f = fixture("legacy_plugin_migration").await;
        let db = &f.appstate.store;
        let (plugin, wasm_file) = legacy_plugin(&f).await;
        let key = PluginMetaKey::new(&f.drive, "ontola", "test-plugin");
        assert!(!db.get_plugin_meta(&key).unwrap().unwrap().has_v2_manifest());
        let installed_at = std::fs::metadata(&wasm_file).unwrap().modified().unwrap();
        assert_eq!(db.get_class_extenders_on_drive(&f.drive).len(), 1);

        assert_eq!(migrate_legacy_plugins(db).await.unwrap(), 1);

        let (id, published, _) = release::publish_package(db, TEST_PLUGIN_ZIP, None)
            .await
            .unwrap();
        let migrated = db.get_resource(&plugin.as_str().into()).await.unwrap();
        let classes = migrated.get(urls::IS_A).unwrap().to_subjects(None).unwrap();
        assert_eq!(classes, vec![urls::INSTALLATION.to_string()]);
        assert_eq!(migrated.get(urls::RELEASE_ID).unwrap().to_string(), id);
        let release_url = migrated.get(urls::RELEASE_PROP).unwrap().to_string();
        assert!(
            release_url.ends_with(&format!("/releases/{id}")),
            "{release_url}"
        );
        assert_eq!(
            migrated.get(urls::INSTALLATION_STATUS).unwrap().to_string(),
            "active"
        );
        let json_of = |prop: &str| -> serde_json::Value {
            serde_json::from_str(&migrated.get(prop).unwrap().to_string()).unwrap()
        };
        assert_eq!(json_of(urls::GRANTS), json!(TEST_PLUGIN_GRANTS));
        assert_eq!(
            json_of(urls::CONFIG),
            json!({"greeting": "hi"}),
            "config is carried over"
        );
        assert!(migrated.get(urls::PLUGIN_FILE).is_err());
        assert_eq!(migrated.get(urls::NAME).unwrap().to_string(), "test-plugin");
        // The release resource exists and resolves to the published release.
        let signer = ForAgent::AgentSubject(db.get_default_agent().unwrap().subject);
        assert_eq!(
            release::resolve(db, &release_url, &signer).await.unwrap(),
            published
        );

        // Same subject, same files, same extender; the meta now holds the
        // unified manifest.
        let meta = db.get_plugin_meta(&key).unwrap().unwrap();
        assert_eq!(meta.subject, plugin);
        assert_eq!(meta.manifest, published.manifest);
        assert_eq!(
            std::fs::metadata(&wasm_file).unwrap().modified().unwrap(),
            installed_at,
            "the migration must not re-extract the package"
        );
        assert_eq!(db.get_class_extenders_on_drive(&f.drive).len(), 1);
        // The extender still fires: the test plugin names every new Folder.
        let folder = genesis(
            db,
            vec![
                (urls::IS_A, Value::ResourceArray(vec![urls::FOLDER.into()])),
                (urls::PARENT, Value::AtomicUrl(f.drive.as_str().into())),
                (urls::NAME, Value::String("before".into())),
            ],
        )
        .await;
        assert!(db.get_resource(&folder.as_str().into()).await.is_ok());
        let shown = db
            .get_resource_extended(&plugin.as_str().into(), false, &ForAgent::Sudo)
            .await
            .unwrap()
            .to_single();
        assert!(shown.get(urls::PLUGIN_AGENT).is_ok());

        // Idempotent: nothing is left to migrate, and nothing changes.
        assert_eq!(migrate_legacy_plugins(db).await.unwrap(), 0);
        let again = db.get_resource(&plugin.as_str().into()).await.unwrap();
        assert_eq!(again.get(urls::RELEASE_ID).unwrap().to_string(), id);
        assert_eq!(
            std::fs::metadata(&wasm_file).unwrap().modified().unwrap(),
            installed_at
        );
    }
}
