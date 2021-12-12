# Atomic-server Tauri

_WARNING: Tauri is not compatible with the currenlty used Actix-Web version, so it does not run / build correctly_.

```sh
# install tauri
yarn global add @tauri/tauri-cli
# run dev server
tauri dev
```

## Limitations

- No way to pass flags to `atomic-sever` using the Tauri executable (although you can set ENV varibles)
- No HTTPS support
