# Atomic-server Tauri

Tauri build Desktop releases for Atomic-Server.
It takes care of native installers, app icons, system tray icons, menu items, self-update ([issue](https://github.com/joepio/atomic-data-rust/issues/158)) and more.

```sh
# install tauri
yarn global add @tauri/tauri-cli
# run dev server
tauri dev
# build an installer for your OS
tauri build
```

## Limitations

- No way to pass flags to `atomic-sever` using the Tauri executable (although you can set ENV varibles)
- No HTTPS support
