/// Add a tray item to the OS bar.
/// Kind of experimental feature.
pub fn tray_icon_process(config: crate::config::Config) {
  let server_url = if config.https {
      format!("https://{}:{}", config.ip.to_string(), config.port_https)
  } else {
      format!("http://{}:{}", config.ip.to_string(), config.port)
  };
  actix_web::rt::spawn(async move {
      let mut tray = match tray_item::TrayItem::new("Atomic", "") {
          Ok(item) => item,
          Err(_e) => return,
      };
      let _ = tray.add_menu_item("Open", move || {
        match open::that(&server_url) {
          Ok(_) => (),
          Err(err) => (
            log::error!("Can't open app. {}", err)
          ),
        }
      });
      let _ = tray.add_menu_item("Config folder", move || {
        match open::that(&config.config_dir) {
          Ok(_) => (),
          Err(err) => (
            log::error!("Can't open config folder. {}", err)
          ),
        }
      });
      let _ = tray.add_menu_item("About", move || {
        match open::that("https://github.com/joepio/atomic") {
          Ok(_) => (),
          Err(err) => (
            log::error!("Can't open about page. {}", err)
          ),
        }
      });
      let inner = tray.inner_mut();
      inner.add_quit_item("Quit");
      inner.display();
  });
}
