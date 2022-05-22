# Atomic-Server Desktop (powered by Tauri)

Desktop release for Atomic-Server.
[Tauri] takes care of native installers, app icons, system tray icons, menu items, self-update ([issue](https://github.com/joepio/atomic-data-rust/issues/158)) and more.

```sh
# install tauri
cargo install tauri-cli
# make sure that `atomic-data-browser` is running on port 8080 (see ## Running in development)
# run dev server
cargo tauri dev
# build an installer for your OS
cargo tauri build
```

## Running in development

By default, the dev server points to `localhost:8080`, which is the server for [`atomic-data-browser`](https://github.com/atomicdata-dev/atomic-data-browser/), which you'll probably want to run.
If you only want to work on the _server side_ of things, you can remove `devPath` in `tauri.conf.json`.

## Limitations

- No way to pass flags to `atomic-sever` using the Tauri executable (although you can set ENV varibles)
- No HTTPS support
