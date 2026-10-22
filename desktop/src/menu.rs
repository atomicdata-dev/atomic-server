#[cfg(target_os = "macos")]
use tauri::menu::AboutMetadata;
use tauri::{
  menu::{Menu, PredefinedMenuItem, Submenu},
  AppHandle, Runtime,
};

pub fn build<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<Menu<R>> {
  let edit_menu = Submenu::with_items(
    app,
    "Edit",
    true,
    &[
      &PredefinedMenuItem::undo(app, None)?,
      &PredefinedMenuItem::redo(app, None)?,
      &PredefinedMenuItem::separator(app)?,
      &PredefinedMenuItem::cut(app, None)?,
      &PredefinedMenuItem::copy(app, None)?,
      &PredefinedMenuItem::paste(app, None)?,
      &PredefinedMenuItem::select_all(app, None)?,
    ],
  )?;

  let view_menu = Submenu::with_items(
    app,
    "View",
    true,
    &[&PredefinedMenuItem::fullscreen(app, None)?],
  )?;

  let window_menu = Submenu::with_items(
    app,
    "Window",
    true,
    &[
      &PredefinedMenuItem::minimize(app, None)?,
      &PredefinedMenuItem::maximize(app, None)?,
    ],
  )?;

  #[cfg(target_os = "macos")]
  {
    let about = PredefinedMenuItem::about(
      app,
      None,
      Some(AboutMetadata {
        name: Some("atomic.place".into()),
        authors: Some(vec!["Joep Meindertsma".into()]),
        copyright: Some("MIT License".into()),
        license: Some("MIT".into()),
        website: Some("https://atomic.place".into()),
        ..Default::default()
      }),
    )?;
    let app_menu = Submenu::with_items(
      app,
      "atomic.place",
      true,
      &[
        &about,
        &PredefinedMenuItem::separator(app)?,
        &PredefinedMenuItem::hide(app, None)?,
        &PredefinedMenuItem::hide_others(app, None)?,
        &PredefinedMenuItem::show_all(app, None)?,
        &PredefinedMenuItem::separator(app)?,
        &PredefinedMenuItem::quit(app, None)?,
      ],
    )?;
    return Menu::with_items(app, &[&app_menu, &edit_menu, &view_menu, &window_menu]);
  }

  #[cfg(not(target_os = "macos"))]
  Menu::with_items(app, &[&edit_menu, &view_menu, &window_menu])
}
