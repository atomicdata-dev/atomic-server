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

## Running in development

By default, the dev server points to `localhost:8080`, which is the server for [`atomic-data-browser`](https://github.com/joepio/atomic-data-browser/), which you'll probably want to run.
If you only want to work on the _server side_ of things, you can remove `devPath` in `tauri.conf.json`.

## Limitations

- No way to pass flags to `atomic-sever` using the Tauri executable (although you can set ENV varibles)
- No HTTPS support
