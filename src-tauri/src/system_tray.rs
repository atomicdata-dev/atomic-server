use tauri::api::shell;
use tauri::{
  AppHandle, CustomMenuItem, SystemTray, SystemTrayEvent, SystemTrayMenu, SystemTrayMenuItem,
  WindowBuilder, WindowUrl,
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
      "open" => app
        .create_window(
          "Atomic Server",
          WindowUrl::App(config.server_url.clone().into()),
          |window_builder, webview_attributes| {
            (window_builder.title("Atomic Data"), webview_attributes)
          },
        )
        .unwrap(),
      "docs" => shell::open("https://docs.atomicdata.dev".into(), None).unwrap(),
      "config" => shell::open(config.config_dir.to_str().unwrap().to_string(), None).unwrap(),
      "browser" => shell::open(config.server_url.clone(), None).unwrap(),
      _ => {}
    }
  }
}
