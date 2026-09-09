#[cfg(feature = "wasm-plugins")]
use std::path::Path;
use std::path::PathBuf;

#[cfg(feature = "wasm-plugins")]
use atomic_lib::urls::{DOWNLOAD_URL, MIMETYPE};
use atomic_lib::{
    agents::{Agent, ForAgent},
    class_extender::{BoxFuture, ClassExtender, CommitExtenderContext, GetExtenderContext},
    db::plugin_meta::{validate_plugin_identifier, validate_plugin_identifiers, PluginMetaKey},
    errors::AtomicResult,
    storelike::ResourceResponse,
    urls::{self},
    AtomicError, Db, Resource, Storelike, Value,
};
#[cfg(feature = "wasm-plugins")]
use tracing::{error, info};
#[cfg(feature = "wasm-plugins")]
use zip::ZipArchive;

#[cfg(feature = "wasm-plugins")]
use crate::plugins::wasm::{install_or_update_plugin, uninstall_plugin};

/// Largest plugin zip we are willing to download from a `downloadURL`.
#[cfg(feature = "wasm-plugins")]
const PLUGIN_DOWNLOAD_MAX_BYTES: usize = 50 * 1024 * 1024;

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
                "Plugin {} has no parent",
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
            "Parent resource for plugin {} is not a drive",
            resource.get_subject()
        )));
    };

    Ok(parent_subject)
}

fn get_namespace_and_name(resource: &Resource) -> AtomicResult<(String, String)> {
    let Ok(Value::String(name)) = resource.get(urls::NAME) else {
        return Err(AtomicError::from(format!(
            "Plugin {} has no name",
            resource.get_subject()
        )));
    };

    let Ok(Value::String(namespace)) = resource.get(urls::NAMESPACE) else {
        return Err(AtomicError::from(format!(
            "Plugin {} has no namespace",
            resource.get_subject()
        )));
    };

    // These values are user-controlled and end up in filesystem paths.
    validate_plugin_identifiers(namespace, name)?;

    Ok((namespace.to_string(), name.to_string()))
}

#[cfg(feature = "wasm-plugins")]
async fn do_uninstall_plugin(
    resource: &Resource,
    parent_subject: &str,
    store: &Db,
    plugins_dir: &Path,
) -> AtomicResult<()> {
    tracing::info!("destroying plugin {}", resource.get_subject());

    // Validates namespace/name so path traversal payloads never reach the filesystem.
    let (namespace, name) = get_namespace_and_name(resource)?;

    tracing::info!(
        "uninstalling plugin {} in namespace {} for drive {}",
        name,
        namespace,
        parent_subject
    );

    // Even if the uninstall fails we still want to continue the commit
    // If we don't do this the resource will not be able to be deleted.
    if let Err(e) = uninstall_plugin(&name, &namespace, parent_subject, store, plugins_dir).await {
        tracing::warn!(
            "Failed to uninstall plugin {}.{} for drive {}: {}",
            namespace,
            name,
            parent_subject,
            e
        );
    }

    Ok(())
}

#[cfg(feature = "wasm-plugins")]
async fn do_install_plugin(
    resource: &Resource,
    parent_subject: &str,
    store: &Db,
    plugins_dir: &Path,
    plugin_cache_dir: &Path,
    uploads_dir: &Path,
    signer: &str,
) -> AtomicResult<()> {
    let plugin_file_subject: String = match resource.get(urls::PLUGIN_FILE)? {
        Value::AtomicUrl(s) => s.to_string(),
        Value::String(s) => s.clone(),
        _ => return Err("Plugin file not found".into()),
    };

    let plugin_file = match store
        .get_resource_extended(
            &plugin_file_subject.clone().into(),
            false,
            &ForAgent::AgentSubject(signer.to_string().into()),
        )
        .await
    {
        Ok(res) => res.to_single(),
        Err(e) => {
            error!(
                "Failed to get plugin file resource {}: {}",
                plugin_file_subject, e
            );
            return Err(e);
        }
    };

    let Value::String(mime_type) = plugin_file.get(MIMETYPE)? else {
        error!(
            "MIME type invalid type for plugin file {}",
            plugin_file_subject
        );
        return Err("MIME type invalid type".into());
    };

    if mime_type != "application/zip" {
        error!(
            "Plugin file {} must be a zip file, got {}",
            plugin_file_subject, mime_type
        );
        return Err("Plugin file must be a zip file".into());
    };

    let internal_id_value = plugin_file.get(urls::INTERNAL_ID).ok();
    let internal_id_str: Option<String> = match internal_id_value {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::AtomicUrl(s)) => Some(s.to_string()),
        _ => None,
    };

    let bytes = if let Some(internal_id) = internal_id_str {
        // Files are stored content-addressed in `Tree::Blobs` (the kv store),
        // keyed by the blake3 hash hex digest. The legacy `uploads_dir/<id>`
        // filesystem path was retired with the content-addressed migration —
        // see server/src/handlers/upload.rs which inserts into `Tree::Blobs`.
        let hash_bytes = match hex::decode(&internal_id) {
            Ok(b) if b.len() == 32 => b,
            _ => {
                error!(
                    "Plugin file {} has internalId that is not a valid blake3 hex hash: {}",
                    plugin_file_subject, internal_id
                );
                // Fall back to the legacy uploads_dir path for any remaining
                // pre-content-addressed file resources.
                let file_path = uploads_dir.join(&internal_id);
                info!("Reading plugin from local file (legacy): {:?}", file_path);
                return Err(AtomicError::from(format!(
                    "Failed to read plugin file locally: {}",
                    std::fs::read(&file_path)
                        .err()
                        .map(|e| e.to_string())
                        .unwrap_or_default()
                )));
            }
        };

        match store
            .kv
            .get(atomic_lib::db::trees::Tree::Blobs, &hash_bytes)
        {
            Ok(Some(bytes)) => {
                info!("Reading plugin from kv blob store ({} bytes)", bytes.len());
                bytes
            }
            Ok(None) => {
                error!(
                    "Plugin file {} blob not found in kv store for hash {}",
                    plugin_file_subject, internal_id
                );
                return Err(AtomicError::from(format!(
                    "Plugin file blob not found in kv store: {}",
                    internal_id
                )));
            }
            Err(e) => {
                return Err(AtomicError::from(format!(
                    "Failed to read plugin blob: {}",
                    e
                )));
            }
        }
    } else {
        let Value::String(download_url) = plugin_file.get(DOWNLOAD_URL)? else {
            error!(
                "Plugin file {} has no internalId and no downloadURL",
                plugin_file_subject
            );
            return Err("Download URL invalid type".into());
        };

        info!("Downloading plugin from: {}", download_url);

        // The URL comes from whoever wrote the plugin-file resource, so this
        // goes through the SSRF guard (no loopback / private / metadata
        // addresses — `ATOMIC_ALLOW_PRIVATE_FETCH=1` lifts that for local
        // plugin development) and the body is capped.
        atomic_lib::client::helpers::fetch_bytes_untrusted(
            download_url.as_str(),
            PLUGIN_DOWNLOAD_MAX_BYTES,
        )
        .await
        .map_err(|e| {
            error!("Failed to download plugin file: {}", e);
            AtomicError::from(format!("Failed to download plugin file: {}", e))
        })?
    };

    info!("Plugin file size: {} bytes", bytes.len());
    if bytes.len() >= 4 {
        info!("First 4 bytes: {:02X?}", &bytes[0..4]);
    } else {
        error!("Downloaded file is too small to be a zip file");
    }

    let mut zip_file = ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| AtomicError::from(format!("Failed to create zip archive: {}", e)))?;

    install_or_update_plugin(
        &mut zip_file,
        parent_subject,
        resource.get_subject().as_str(),
        store,
        plugins_dir,
        plugin_cache_dir,
    )
    .await?;

    Ok(())
}

#[allow(unused_variables)]
fn on_before_commit(
    context: CommitExtenderContext,
    plugins_dir: PathBuf,
    plugin_cache_dir: PathBuf,
    uploads_dir: PathBuf,
) -> BoxFuture<AtomicResult<()>> {
    Box::pin(async move {
        let CommitExtenderContext {
            store,
            commit,
            resource,
            is_new,
            changed_props,
        } = context;

        // Gets the parent drive and returns an error if the parent is not a drive.
        let parent_subject = get_parent_drive(resource, store).await?;

        // If the plugin is being deleted, uninstall it.
        if commit.destroy == Some(true) {
            #[cfg(feature = "wasm-plugins")]
            do_uninstall_plugin(resource, &parent_subject, store, &plugins_dir).await?;
            return Ok(());
        }

        if !changed_props.is_empty() {
            // If the plugin is not new, we don't allow updating values that identify the plugin as that could lead to corrupted state.
            if !is_new {
                if changed_props.contains(urls::NAME) || changed_props.contains(urls::NAMESPACE) {
                    return Err(AtomicError::from(
                        "Cannot update plugin namespace/name after it has been created",
                    ));
                }

                if changed_props.contains(urls::PARENT) {
                    return Err(AtomicError::from(
                        "Cannot update plugin parent after it has been created",
                    ));
                }
            } else {
                // Reject unsafe identifiers at creation time, so a traversal payload can never be
                // stored and later reach the uninstall path.
                for (field, prop) in [("name", urls::NAME), ("namespace", urls::NAMESPACE)] {
                    if let Ok(Value::String(value)) = resource.get(prop) {
                        validate_plugin_identifier(field, value)?;
                    }
                }

                // For new plugins, check if name/namespace are already used on this drive.
                if let Ok((namespace, name)) = get_namespace_and_name(resource) {
                    let key = PluginMetaKey::new(&parent_subject, &namespace, &name);
                    if let Some(meta) = store.get_plugin_meta(&key)? {
                        if meta.subject.as_str() != resource.get_subject().as_str() {
                            return Err(AtomicError::from(format!(
                                "A plugin with the name '{}' and namespace '{}' is already installed on this drive.",
                                name, namespace
                            )));
                        }
                    }
                }
            }

            // The plugin file has been set or updated, so we need to (re)install the plugin.
            #[cfg(feature = "wasm-plugins")]
            if changed_props.contains(urls::PLUGIN_FILE) {
                tracing::info!(
                    "New plugin file found for plugin {}, installing...",
                    resource.get_subject()
                );

                do_install_plugin(
                    resource,
                    &parent_subject,
                    store,
                    &plugins_dir,
                    &plugin_cache_dir,
                    &uploads_dir,
                    commit.signer.as_str(),
                )
                .await?;
            }
        }

        Ok(())
    })
}

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

        // Populate the resource with the data from the plugin manifest.
        db_resource.set_unsafe(
            urls::PLUGIN_AGENT.to_string(),
            Value::AtomicUrl(agent.subject.clone()),
        )?;

        db_resource
            .set(
                urls::VERSION.to_string(),
                Value::String(meta.manifest.version.clone()),
                store,
            )
            .await?;

        if let Some(description) = meta.manifest.description {
            db_resource
                .set(
                    urls::DESCRIPTION.to_string(),
                    Value::Markdown(description),
                    store,
                )
                .await?;
        }

        if let Some(author) = meta.manifest.author {
            db_resource
                .set(
                    urls::PLUGIN_AUTHOR.to_string(),
                    Value::String(author),
                    store,
                )
                .await?;
        }

        if let Some(permissions) = meta.manifest.permissions {
            db_resource
                .set(
                    urls::PLUGIN_PERMISSIONS.to_string(),
                    Value::Json(serde_json::to_value(permissions)?),
                    store,
                )
                .await?;
        }

        if let Some(json_schema) = meta.manifest.config_schema {
            db_resource
                .set(
                    urls::JSON_SCHEMA.to_string(),
                    Value::Json(serde_json::to_value(json_schema)?),
                    store,
                )
                .await?;
        }

        Ok(db_resource.clone().into())
    })
}

pub fn build_plugin_extender(
    plugins_dir: PathBuf,
    plugin_cache_dir: PathBuf,
    uploads_dir: PathBuf,
) -> ClassExtender {
    ClassExtender::builder()
        .id("plugin".to_string())
        .classes(vec![urls::PLUGIN.to_string()])
        .on_resource_get(ClassExtender::wrap_get_handler(move |context| {
            on_resource_get(context)
        }))
        .before_commit(ClassExtender::wrap_commit_handler(move |context| {
            on_before_commit(
                context,
                plugins_dir.clone(),
                plugin_cache_dir.clone(),
                uploads_dir.clone(),
            )
        }))
        .build()
}
