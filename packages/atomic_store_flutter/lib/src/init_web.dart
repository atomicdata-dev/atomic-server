Future<void> initRustBridge() async {
  // FRB WASM requires SharedArrayBuffer (COOP/COEP headers) which Flutter's
  // dev server doesn't support, and `dart:ffi` is unavailable. There is no
  // native node on the web: use a StoreBackend over HTTP there.
}
