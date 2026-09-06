// Menus and the tray are desktop concepts — `set_menu` and `TrayIcon` do not
// exist on mobile. These were gated `not(android)`, which still let them
// through on iOS; nothing caught it because iOS has never been built.
#[cfg(desktop)]
mod menu;
#[cfg(desktop)]
mod system_tray;
// The NFS virtual drive is unix-desktop-only: mobile can't mount NFS, and
// `nfsserve` does not build for windows (see the dependency note in
// Cargo.toml). `desktop` here is the alias tauri-build sets, i.e. not mobile.
#[cfg(all(desktop, unix))]
mod vfs;

/// Hand the Android system certificate verifier the app's JVM context.
/// reqwest's rustls backend panics on any outbound HTTPS request until this
/// runs. Requires the `rustls:rustls-platform-verifier` Kotlin component
/// bundled via gradle (see gen/android/build.gradle.kts).
///
/// The raw pointers come from wry's JNI callback (jni 0.21 types); they are
/// rebuilt here as the jni 0.22 types rustls-platform-verifier expects.
#[cfg(target_os = "android")]
fn init_tls_verifier(raw_vm: *mut std::ffi::c_void, raw_activity: *mut std::ffi::c_void) {
  let vm = unsafe { jni::JavaVM::from_raw(raw_vm.cast()) };
  vm.attach_current_thread(|env| -> Result<(), jni::errors::Error> {
    let activity = unsafe { jni::objects::JObject::from_raw(env, raw_activity.cast()) };
    rustls_platform_verifier::android::init_with_env(env, activity)
  })
  .expect("failed to initialize rustls-platform-verifier");
}

/// A name for this phone/tablet to introduce itself with when it syncs.
///
/// Android's hostname is always `localhost`, which is what `effective_device_name`
/// falls back to — so without this, every paired Android shows up in the other
/// device's Sync page as "localhost". `ro.product.marketname` is the name a
/// vendor gives the retail device ("Xiaomi Pad 6"); stock Android doesn't set
/// it, so fall back to the model ("Pixel 8").
#[cfg(target_os = "android")]
fn android_device_name() -> Option<String> {
  let props = android_system_properties::AndroidSystemProperties::new();

  ["ro.product.marketname", "ro.product.model"]
    .iter()
    .find_map(|key| props.get(key))
    .map(|name| name.trim().to_string())
    .filter(|name| !name.is_empty())
}

/// Deep links (`atomic://pair?p=…`, see `planning/device-pairing.md`) are
/// forwarded to the webview as `atomic-deep-link` DOM events; the frontend
/// captures them from module scope (`helpers/deepLinkQueue.ts`). A link can
/// arrive before the page has loaded — the cold start from the system camera
/// scanning a pairing QR — and an eval into a not-yet-loaded page is silently
/// lost (and `on_page_load` never fires on Android, so there is no reliable
/// "page ready" callback). So delivery is at-least-once: pending links are
/// re-dispatched every few seconds for a couple of minutes, and the frontend
/// dedupes by URI, handling each link exactly once.
#[derive(Default)]
struct PairLinks {
  pending: std::sync::Mutex<Vec<String>>,
}

fn queue_pair_links(state: &PairLinks, urls: impl IntoIterator<Item = String>) {
  let mut pending = state.pending.lock().unwrap();
  for url in urls {
    if url.starts_with("atomic://") && !pending.contains(&url) {
      println!("[pairing] queued deep link");
      pending.push(url);
    }
  }
}

fn dispatch_pair_links(eval: impl Fn(&str) -> tauri::Result<()>, state: &PairLinks) {
  let links: Vec<String> = state.pending.lock().unwrap().clone();
  for link in links {
    let js = format!(
      "window.dispatchEvent(new CustomEvent('atomic-deep-link', {{ detail: {} }}));",
      serde_json::to_string(&link).expect("a string always serializes")
    );
    let _ = eval(&js);
  }
}

/// How long a link keeps being re-dispatched. Generous so a slow cold start
/// (first boot builds the store) still gets its link; the frontend's dedupe
/// makes the repeats free.
const PAIR_LINK_RETRY_WINDOW: std::time::Duration = std::time::Duration::from_secs(120);

/// A handle on the embedded node, captured once it has booted.
#[derive(Default)]
struct EmbeddedNode {
  store: std::sync::OnceLock<atomic_lib::Db>,
  config_file: std::sync::OnceLock<std::path::PathBuf>,
  /// Why the node never came up, if it didn't. The server runs on its own
  /// thread, so a boot failure there used to be an unwind into nothing: the
  /// window stayed open, `store` stayed empty, and every node-backed feature
  /// reported "still starting up" forever. Recording the reason lets the UI say
  /// what actually went wrong.
  startup_error: std::sync::OnceLock<String>,
}

impl EmbeddedNode {
  /// The store, or an explanation of why there isn't one.
  fn require_store(&self) -> Result<atomic_lib::Db, String> {
    if let Some(store) = self.store.get() {
      return Ok(store.clone());
    }

    Err(match self.startup_error.get() {
      Some(error) => format!("The local node failed to start: {error}"),
      None => "The local node has not finished starting up.".to_string(),
    })
  }
}

/// Turn a store-open failure into advice, because the common cause has a cure
/// the message doesn't hint at. The desktop app and a command-line
/// `atomic-server` default to the same data directory, and the store may only be
/// opened once — so a server left running in a terminal keeps the app's node
/// locked out.
fn explain_startup_failure(error: &str) -> String {
  if error.contains("Database already open") {
    format!(
      "{error}\n\nAnother atomic-server is already using this data directory. \
       Quit it (or start it with --data-dir pointing elsewhere) and restart the app."
    )
  } else {
    error.to_string()
  }
}

/// Make this device's node act as the signed-in user, rather than as the
/// identity `atomic-server` mints for itself on first boot.
///
/// On a hosted server, the server is a principal: it has an agent, it signs,
/// and it is root over its own store (`hierarchy.rs`, "Server agent has root
/// access"). On a personal device that is simply false — the user is the
/// principal. Left alone, the embedded server signs peer AUTH as a stranger,
/// every remote `check_read` denies it, and sync moves nothing.
///
/// This is a Tauri command and deliberately **not** an HTTP endpoint. The
/// embedded server listens on `localhost`, which on Android any other app can
/// reach; an endpoint that sets the node's root identity would be a handover of
/// the device. Tauri IPC is callable only from our own webview.
///
/// Persisted, because the browser cannot supply it twice: the agent's private
/// key is stored non-extractable (`helpers/agentStorage.ts`), so sign-in is the
/// one moment the secret exists outside the keystore.
#[tauri::command]
async fn adopt_agent(
  secret: String,
  node: tauri::State<'_, std::sync::Arc<EmbeddedNode>>,
) -> Result<(), String> {
  let store = node.require_store()?;
  let config_file = node
    .config_file
    .get()
    .ok_or("The local node has no config path.")?
    .clone();

  use atomic_lib::Storelike;
  store
    .load_agent_from_secret(&secret)
    .await
    .map_err(|e| format!("Could not adopt that agent: {e}"))?;

  let mut config = atomic_lib::config::read_config(Some(&config_file))
    .map_err(|e| format!("Could not read the node config: {e}"))?;
  config.shared.agent_secret = secret;
  config.shared.initial_drive = store
    .get_default_agent()
    .ok()
    .and_then(|agent| agent.initial_drive.map(|d| d.to_string()));
  config
    .save(&config_file)
    .map_err(|e| format!("Could not persist the node agent: {e}"))?;

  println!("[identity] the local node now acts as the signed-in agent");

  Ok(())
}

/// Cloud Vault, against the embedded node's own store.
///
/// In a browser the vault runs inside the WASM ClientDb, because that *is* the
/// local database there. This app has no ClientDb — the embedded server already
/// persists everything, and running an OPFS copy alongside it would mean two
/// databases holding the same drive. So the same `atomic_lib::vault` functions
/// are called here against the node's store instead: one copy of the data, one
/// implementation of the format.
///
/// Tauri commands rather than HTTP endpoints, for the reason `adopt_agent`
/// gives above: the embedded server listens on `localhost`, which on Android
/// any other app can reach, and these take the drive's encryption key. Tauri
/// IPC is callable only from our own webview.
///
/// Only sealing moves here. The network half — presigned URLs, uploads, and
/// the agent-signed proof the control plane checks — stays in JS, where the
/// agent's key already lives (see `helpers/managed/vault.ts`).
///
/// Keys and sealed bytes cross the IPC boundary base64-encoded rather than as
/// byte arrays. Deliberate: a `Vec<u8>` renders as a JSON number array here,
/// and getting exactly that wrong at the WASM boundary is what silently stored
/// a stringified array in every vault object once already.
mod vault_ipc {
  pub use atomic_lib::vault::{
    dek::DriveVaultKey,
    store::{MemoryVaultStore, VaultObjectStore},
    sync::{
      commit_lane_state, drive_prefix, export_vault_segment, import_vault_batch, CheckpointPolicy,
      SegmentKind,
    },
  };
  pub use base64::engine::general_purpose::STANDARD;
  use base64::Engine as _;

  #[derive(serde::Deserialize)]
  #[serde(rename_all = "camelCase")]
  pub struct VaultObjectIn {
    pub object_key: String,
    /// base64
    pub sealed: String,
  }

  #[derive(serde::Serialize)]
  #[serde(rename_all = "camelCase")]
  pub struct VaultExportOut {
    pub object_key: String,
    /// base64
    pub sealed: String,
    /// `"pack"` or `"checkpoint"` — decides which object the control plane is
    /// asked for an upload URL for, and whether the caller must publish the
    /// checkpoint afterwards.
    pub kind: &'static str,
    pub resources: usize,
    /// Resources skipped because their version vector still matched the lane
    /// cursor. The measure of how much an incremental pass saved.
    pub unchanged: usize,
    pub tombstones: usize,
    /// Checkpoints only: the lanes this object provably subsumes, which is what
    /// `POST /checkpoint` publishes and what pruning acts on.
    pub coverage: std::collections::BTreeMap<String, u32>,
  }

  pub fn kind_name(kind: SegmentKind) -> &'static str {
    match kind {
      SegmentKind::Pack => "pack",
      SegmentKind::Checkpoint => "checkpoint",
    }
  }

  #[derive(serde::Serialize)]
  #[serde(rename_all = "camelCase")]
  pub struct VaultImportOut {
    pub packs_read: usize,
    pub resources_restored: usize,
    pub tombstones_applied: usize,
    /// Objects the newest checkpoint already subsumed, so they were never read.
    pub objects_skipped: usize,
    /// Objects that would not open. Non-zero means part of the vault is corrupt
    /// or foreign; everything else still restored.
    pub objects_unreadable: usize,
  }

  pub fn decode_key(key_b64: &str, epoch: u32) -> Result<DriveVaultKey, String> {
    let raw = STANDARD
      .decode(key_b64)
      .map_err(|e| format!("drive vault key is not valid base64: {e}"))?;
    let bytes: [u8; 32] = raw
      .try_into()
      .map_err(|_| "drive vault key must be exactly 32 bytes".to_string())?;

    Ok(DriveVaultKey::from_bytes(bytes, epoch))
  }

  pub fn store_of(node: &std::sync::Arc<super::EmbeddedNode>) -> Result<atomic_lib::Db, String> {
    node
      .store
      .get()
      .ok_or_else(|| "The local node has not finished starting up.".to_string())
      .cloned()
  }

  /// Run vault work on a thread of its own.
  ///
  /// `export_vault_segment` and `import_vault_batch` borrow a `&dyn
  /// VaultObjectStore` across their awaits, so their futures are not `Send` and
  /// cannot live in a Tauri command's future directly. Giving them a
  /// current-thread runtime keeps that constraint where it belongs instead of
  /// pushing `Send` bounds through the vault API for one caller's benefit.
  ///
  /// It also keeps a large export off the UI thread, which a synchronous
  /// command would not.
  pub async fn on_worker_thread<T, F>(work: F) -> Result<T, String>
  where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
  {
    let (tx, rx) = tokio::sync::oneshot::channel();

    std::thread::spawn(move || {
      let _ = tx.send(work());
    });

    rx.await
      .map_err(|_| "The vault worker stopped before it answered.".to_string())?
  }

  /// A current-thread runtime for one non-`Send` future.
  pub fn block_on<F: std::future::Future>(future: F) -> Result<F::Output, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .map_err(|e| format!("Could not start the vault worker: {e}"))?;

    Ok(runtime.block_on(future))
  }
}

/// Seal this drive's history into one vault object.
///
/// `None` when the drive has not changed since the last segment, so a periodic
/// backup skips the upload instead of storing an empty object every tick.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn vault_export(
  drive_subject: String,
  key: String,
  key_epoch: u32,
  drive_pseudonym: String,
  device_pubkey: String,
  segment: u32,
  checkpoint_n: u64,
  drive_has_checkpoint: bool,
  observed_lanes: std::collections::BTreeMap<String, u32>,
  node: tauri::State<'_, std::sync::Arc<EmbeddedNode>>,
) -> Result<Option<vault_ipc::VaultExportOut>, String> {
  let store = vault_ipc::store_of(&node)?;
  let key = vault_ipc::decode_key(&key, key_epoch)?;

  vault_ipc::on_worker_thread(move || {
    use atomic_lib::Storelike as _;
    use base64::Engine as _;
    use vault_ipc::{VaultObjectStore as _, STANDARD};

    let subject = atomic_lib::Subject::from_raw(&drive_subject, store.get_base_domain().as_deref());
    let staging = vault_ipc::MemoryVaultStore::new();

    let summary = vault_ipc::block_on(vault_ipc::export_vault_segment(
      &store,
      &subject,
      &key,
      &staging,
      &drive_pseudonym,
      &device_pubkey,
      segment,
      checkpoint_n,
      drive_has_checkpoint,
      &observed_lanes,
      vault_ipc::CheckpointPolicy::default(),
    ))?
    .map_err(|e| format!("Could not seal this drive: {e}"))?;

    let Some(summary) = summary else {
      return Ok(None);
    };

    let sealed = staging
      .get(&summary.object_key)
      .map_err(|e| format!("Sealed object went missing before it could be read: {e}"))?;

    Ok(Some(vault_ipc::VaultExportOut {
      sealed: STANDARD.encode(&sealed),
      object_key: summary.object_key,
      kind: vault_ipc::kind_name(summary.kind),
      resources: summary.resources,
      unchanged: summary.unchanged,
      tombstones: summary.tombstones,
      coverage: summary.coverage,
    }))
  })
  .await
}

/// Record that a sealed segment is durably in the vault.
///
/// Separate from `vault_export` on purpose: until this is called the lane's
/// progress stays provisional, so an upload that failed is retried against the
/// same view of what has been backed up rather than one that assumed success.
#[tauri::command]
async fn vault_commit_segment(
  drive_pseudonym: String,
  device_pubkey: String,
  segment: u32,
  node: tauri::State<'_, std::sync::Arc<EmbeddedNode>>,
) -> Result<(), String> {
  let store = vault_ipc::store_of(&node)?;

  vault_ipc::commit_lane_state(&store, &drive_pseudonym, &device_pubkey, segment)
    .map_err(|e| format!("Could not record the segment: {e}"))
}

/// Merge downloaded vault objects into the node's store.
///
/// Objects are applied in the order given, so the caller must pass them sorted
/// by key: a later segment's deletion has to win over an earlier segment's copy
/// of the same resource.
#[tauri::command]
async fn vault_import(
  key: String,
  key_epoch: u32,
  drive_pseudonym: String,
  device_pubkey: String,
  objects: Vec<vault_ipc::VaultObjectIn>,
  node: tauri::State<'_, std::sync::Arc<EmbeddedNode>>,
) -> Result<vault_ipc::VaultImportOut, String> {
  let store = vault_ipc::store_of(&node)?;
  let key = vault_ipc::decode_key(&key, key_epoch)?;

  vault_ipc::on_worker_thread(move || {
    use base64::Engine as _;
    use vault_ipc::{VaultObjectStore as _, STANDARD};

    let staging = vault_ipc::MemoryVaultStore::new();

    for object in &objects {
      let sealed = STANDARD.decode(&object.sealed).map_err(|e| {
        format!(
          "Vault object {} is not valid base64: {e}",
          object.object_key
        )
      })?;
      staging
        .put(&object.object_key, &sealed)
        .map_err(|e| format!("Could not stage vault object {}: {e}", object.object_key))?;
    }

    let summary = vault_ipc::block_on(vault_ipc::import_vault_batch(
      &store,
      &key,
      &staging,
      &vault_ipc::drive_prefix(&drive_pseudonym),
      Some((&drive_pseudonym, &device_pubkey)),
    ))?
    .map_err(|e| format!("Could not restore from the vault: {e}"))?;

    Ok(vault_ipc::VaultImportOut {
      packs_read: summary.packs_read,
      resources_restored: summary.resources_restored,
      tombstones_applied: summary.tombstones_applied,
      objects_skipped: summary.objects_skipped,
      objects_unreadable: summary.objects_unreadable,
    })
  })
  .await
}

/// Start the read-only NFS virtual drive (desktop only — mobile can't mount
/// NFS). Returns the current status, including the `mount` command to run.
#[cfg(all(desktop, unix))]
#[tauri::command]
fn virtual_drive_start(
  node: tauri::State<'_, std::sync::Arc<EmbeddedNode>>,
  vfs: tauri::State<'_, std::sync::Arc<vfs::VfsController>>,
) -> Result<vfs::VfsStatus, String> {
  let store = node.require_store()?;
  vfs.start(store)?;

  Ok(vfs.status())
}

#[cfg(all(desktop, unix))]
#[tauri::command]
fn virtual_drive_stop(vfs: tauri::State<'_, std::sync::Arc<vfs::VfsController>>) -> vfs::VfsStatus {
  vfs.stop();
  vfs.status()
}

#[cfg(all(desktop, unix))]
#[tauri::command]
fn virtual_drive_status(
  vfs: tauri::State<'_, std::sync::Arc<vfs::VfsController>>,
) -> vfs::VfsStatus {
  vfs.status()
}

/// Open the mounted virtual drive in the OS file manager.
#[cfg(all(desktop, unix))]
#[tauri::command]
fn virtual_drive_open() -> Result<(), String> {
  vfs::open_mount()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  let builder = tauri::Builder::default()
    .plugin(tauri_plugin_deep_link::init())
    .plugin(tauri_plugin_process::init())
    .plugin(tauri_plugin_opener::init());

  // Lets an agent drive this window over a WebSocket — open a document, type,
  // read back the DOM — so collaborative editing can be tested end to end
  // without a person at the keyboard. Debug builds only.
  //
  // Bound to loopback rather than the plugin's default `0.0.0.0`: this is an
  // unauthenticated channel that can execute JS in the webview, and on a café
  // network the default would offer that to everyone on the subnet.
  #[cfg(debug_assertions)]
  let builder = builder.plugin(
    tauri_plugin_mcp_bridge::Builder::new()
      .bind_address("127.0.0.1")
      .build(),
  );

  // In-app QR scanner for device pairing (Android/iOS only).
  #[cfg(mobile)]
  let builder = builder.plugin(tauri_plugin_barcode_scanner::init());

  let node = std::sync::Arc::new(EmbeddedNode::default());
  let node_for_server = node.clone();

  let builder = builder.manage(PairLinks::default()).manage(node);

  // The virtual-drive NFS mount is desktop-only; register its state + commands
  // only there (mobile can't mount NFS).
  #[cfg(all(desktop, unix))]
  let builder = builder
    .manage(std::sync::Arc::new(vfs::VfsController::default()))
    .invoke_handler(tauri::generate_handler![
      adopt_agent,
      vault_export,
      vault_commit_segment,
      vault_import,
      virtual_drive_start,
      virtual_drive_stop,
      virtual_drive_status,
      virtual_drive_open
    ]);
  #[cfg(not(all(desktop, unix)))]
  let builder = builder.invoke_handler(tauri::generate_handler![
    adopt_agent,
    vault_export,
    vault_commit_segment,
    vault_import
  ]);

  builder
    .setup(move |app| {
      {
        use tauri::Manager;
        use tauri_plugin_deep_link::DeepLinkExt;
        let handle = app.handle().clone();
        app.deep_link().on_open_url(move |event| {
          println!("[pairing] deep link received");
          let state = handle.state::<PairLinks>();
          queue_pair_links(&state, event.urls().iter().map(|u| u.to_string()));
          // Warm case: page is loaded, deliver right away. The retry loop
          // below covers the cold start.
          if let Some(webview) = handle.get_webview_window("main") {
            dispatch_pair_links(|js| webview.eval(js), &state);
          }
        });

        // At-least-once delivery loop (see PairLinks doc-comment).
        let retry_handle = app.handle().clone();
        std::thread::spawn(move || {
          let started = std::time::Instant::now();
          while started.elapsed() < PAIR_LINK_RETRY_WINDOW {
            std::thread::sleep(std::time::Duration::from_secs(3));
            let state = retry_handle.state::<PairLinks>();
            // Cold start: the launching intent may predate the on_open_url
            // registration; get_current recovers it.
            if let Ok(Some(urls)) = retry_handle.deep_link().get_current() {
              queue_pair_links(&state, urls.iter().map(|u| u.to_string()));
            }
            if let Some(webview) = retry_handle.get_webview_window("main") {
              dispatch_pair_links(|js| webview.eval(js), &state);
            }
          }
          retry_handle
            .state::<PairLinks>()
            .pending
            .lock()
            .unwrap()
            .clear();
        });
      }

      // The verifier init must run on the Android context thread (via wry's
      // JNI dispatch); the server thread below waits for it so no HTTPS
      // request can hit an uninitialized verifier.
      #[cfg(target_os = "android")]
      let tls_verifier_ready = {
        use tauri::Manager;
        let (tx, rx) = std::sync::mpsc::channel();
        let webview = app
          .get_webview_window("main")
          .expect("main window should exist");
        webview.with_webview(move |platform_webview| {
          platform_webview
            .jni_handle()
            .exec(move |env, activity, _webview| {
              let raw_vm = env
                .get_java_vm()
                .expect("JavaVM from JNI env")
                .get_java_vm_pointer();
              init_tls_verifier(raw_vm.cast(), activity.as_raw().cast());
              let _ = tx.send(());
            });
        })?;
        rx
      };
      #[cfg(target_os = "android")]
      let config = {
        use tauri::Manager;
        let paths = app.path();
        let data_dir = paths.app_data_dir().expect("no app data dir");
        let config_dir = paths.app_config_dir().expect("no app config dir");
        let cache_dir = paths.app_cache_dir().expect("no app cache dir");
        use clap::Parser;
        let mut opts = atomic_server_lib::config::Opts::parse_from([
          "atomic-server",
          "--data-dir",
          data_dir.to_str().unwrap(),
          "--config-dir",
          config_dir.to_str().unwrap(),
          "--cache-dir",
          cache_dir.to_str().unwrap(),
        ]);
        // `serve` persists this, so peers see the device rather than "localhost".
        if opts.device_name.is_none() {
          opts.device_name = android_device_name();
        }
        atomic_server_lib::config::build_config(opts)
          .map_err(|e| format!("Initialization failed: {}", e))
          .expect("failed init config")
      };

      #[cfg(not(target_os = "android"))]
      let config = {
        let opts = atomic_server_lib::config::read_opts();
        atomic_server_lib::config::build_config(opts)
          .map_err(|e| format!("Initialization failed: {}", e))
          .expect("failed init config")
      };

      let config_clone = config.clone();
      let _ = node_for_server
        .config_file
        .set(config.config_file_path.clone());
      // This is not the cleanest solution, but running actix inside the tauri / tokio runtime is not
      std::thread::spawn(move || {
        #[cfg(target_os = "android")]
        tls_verifier_ready
          .recv()
          .expect("TLS verifier initialization did not complete");

        let rt = actix_rt::Runtime::new().unwrap();
        // The hook hands us the store once it's up, so `adopt_agent` can point
        // the node's identity at the signed-in user.
        let result = rt.block_on(atomic_server_lib::serve::serve_with_hook(
          config_clone,
          |appstate| {
            let _ = node_for_server.store.set(appstate.store.clone());
          },
        ));

        // Don't panic: this thread has no one to unwind to, and the window
        // outlives it either way. Record the reason so the UI can show it.
        if let Err(e) = result {
          let reason = explain_startup_failure(&e.to_string());
          eprintln!("[node] the embedded server stopped: {reason}");
          let _ = node_for_server.startup_error.set(reason);
        }
      });

      #[cfg(desktop)]
      {
        let menu = crate::menu::build(app.handle())?;
        app.handle().set_menu(menu)?;
        system_tray::setup(app, &config)?;
      }

      Ok(())
    })
    .run(tauri::generate_context!())
    .expect("Tauri Error.");
}
