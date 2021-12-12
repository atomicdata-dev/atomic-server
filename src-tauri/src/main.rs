mod menu;
mod system_tray;

pub async fn test() {
  println!("test local");
}

fn main() {
  let ctx = tauri::generate_context!();

  let config: atomic_server_lib::config::Config = atomic_server_lib::config::init()
    .map_err(|e| format!("Initialization failed: {}", e))
    .expect("failed init config");

  // Find a way to combine actix and tauri runtimes...
  {
    // let config_clone = config.clone();
    // atomic_server_lib::serve::serve(&config_clone);
  }
  tauri::Builder::default()
    .menu(crate::menu::build(&ctx))
    .on_menu_event(crate::menu::handle)
    .system_tray(crate::system_tray::build())
    .on_system_tray_event(move |e, h| {
      let cfg = config.clone();
      crate::system_tray::handle(e, h, &cfg)
    })
    .run(ctx)
    .expect("Tauri Error.");
}
