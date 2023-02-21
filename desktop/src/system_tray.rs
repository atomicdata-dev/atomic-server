use tauri::{
  api::shell, window::WindowBuilder, AppHandle, CustomMenuItem, Manager, SystemTray,
  SystemTrayEvent, SystemTrayMenu, SystemTrayMenuItem, WindowUrl,
};

pub fn build() -> SystemTray {
  let tray_menu = SystemTrayMenu::new()
    .add_item(CustomMenuItem::new("open", "Open"))
    .add_item(CustomMenuItem::new(
      "browser".to_string(),
      "Open in browser",
    ))
    .add_item(CustomMenuItem::new("config".to_string(), "Config folder"))
    .add_item(CustomMenuItem::new("docs".to_string(), "Atomic Data Docs"))
    .add_native_item(SystemTrayMenuItem::Separator)
    .add_item(CustomMenuItem::new("quit".to_string(), "Quit"));
  SystemTray::new().with_menu(tray_menu)
}

pub fn handle(
  app: &'_ AppHandle,
  event: SystemTrayEvent,
  config: &atomic_server_lib::config::Config,
) {
  if let SystemTrayEvent::MenuItemClick { id, .. } = event {
    match id.as_str() {
      "quit" => {
        std::process::exit(0);
      }
      "open" => {
        WindowBuilder::new(
          app,
          "Atomic Server",
          WindowUrl::App(config.server_url.clone().into()),
        );
      }
      "docs" => shell::open(&app.shell_scope(), "https://docs.atomicdata.dev", None).unwrap(),
      "config" => shell::open(
        &app.shell_scope(),
        config.config_dir.to_str().unwrap(),
        None,
      )
      .unwrap(),
      "browser" => shell::open(&app.shell_scope(), &config.server_url, None).unwrap(),
      _ => {}
    }
  }
}
