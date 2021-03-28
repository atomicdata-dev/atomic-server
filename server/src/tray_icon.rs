/// Add a tray item to the OS bar.
/// Kind of experimental feature.
pub fn tray_icon_process(config: crate::config::Config) {
  let server_url = if config.https {
      format!("https://{}:{}", config.ip.to_string(), config.port_https)
  } else {
      format!("http://{}:{}", config.ip.to_string(), config.port)
  };
  actix_rt::spawn(async move {
      let mut tray = match tray_item::TrayItem::new("Atomic", "") {
          Ok(item) => item,
          Err(_e) => return,
      };
      let _ = tray.add_menu_item("Open", move || {
        open::that(&server_url);
      });
      let _ = tray.add_menu_item("Config folder", move || {
        open::that(&config.config_dir);
      });
      let _ = tray.add_menu_item("About", move || {
        open::that("https://github.com/joepio/atomic");
      });
      let inner = tray.inner_mut();
      inner.add_quit_item("Quit");
      inner.display();
  });
}
