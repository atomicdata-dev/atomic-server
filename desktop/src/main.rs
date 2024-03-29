mod menu;
mod system_tray;

fn main() {
  let ctx = tauri::generate_context!();

  let opts = atomic_server_lib::config::read_opts();
  let config: atomic_server_lib::config::Config = atomic_server_lib::config::build_config(opts)
    .map_err(|e| format!("Initialization failed: {}", e))
    .expect("failed init config");
  let config_clone = config.clone();

  // This is not the cleanest solution, but running actix inside the tauri / tokio runtime is not
  std::thread::spawn(move || {
    let rt = actix_rt::Runtime::new().unwrap();
    rt.block_on(atomic_server_lib::serve::serve(config_clone))
      .unwrap();
  });

  tauri::Builder::default()
    .menu(crate::menu::build(&ctx))
    .system_tray(crate::system_tray::build())
    .on_system_tray_event(move |a, h| crate::system_tray::handle(a, h, &config))
    .run(ctx)
    .expect("Tauri Error.");
}
