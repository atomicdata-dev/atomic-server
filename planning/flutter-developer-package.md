# Flutter developer package

Goal: a third-party app (or an AI agent) adds one Flutter package and has a
working `Store` on the Rust `atomic_lib` node, with no Rust or
`flutter_rust_bridge` knowledge.

Result: `packages/atomic_store_flutter` (entry point `AtomicFlutter.init()` /
`AtomicFlutter.open(...)`), example in `packages/atomic_store_flutter/example`.

- [x] Move the Rust crate (`flutter/rust`), the cargokit FFI plugin
      (`flutter/rust_builder`), the generated Dart (`flutter/lib/bridge`),
      `flutter_rust_bridge.yaml` and `BridgeStoreBackend` into the package (git mv)
- [x] Plugin and package renamed `atomic_store_flutter` (podspecs, gradle,
      CMake); crate and native library keep the name `atomic_flutter_rust`
- [x] `AtomicFlutter` / `AtomicNode` entry point; public generated bridge in `lib/bridge/`
- [x] App depends on the package; imports switched to
      `package:atomic_store_flutter/...`; `rust_init*` removed (unused)
- [x] Root `Cargo.toml` exclude, dagger `flutterTest`, workflows, docs updated
- [x] Regenerate with codegen 2.12.0; `git diff` clean after a second run
- [x] `example/` (hello_atomic) passes `flutter analyze`; CI job `example`
- [ ] Linux build of the example (needs > 3 GB free; not tried in the sandbox)
- [ ] Typed Dart wrappers for files, history, peers (raw bridge only today)
- [ ] Publish to pub.dev / prebuilt native binaries (cargokit precompiled
      binaries) so a first build does not compile `atomic_lib` for ~10 minutes
- [ ] Make Iroh peer sync usable from a node other than the default store
