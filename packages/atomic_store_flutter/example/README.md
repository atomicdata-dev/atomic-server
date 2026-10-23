# hello_atomic

The smallest app on Atomic Data: it opens a local node, creates a resource,
names it, saves it, reads it back and watches it live (`lib/main.dart`, about
100 lines). Rename the resource in the text field and the watcher updates.

## From an empty folder to a running app

1. Install the prerequisites:
   - [Flutter](https://docs.flutter.dev/get-started/install) 3.24 or newer;
   - [Rust via rustup](https://rustup.rs) (the build compiles a Rust library;
     rustup fetches the toolchain pinned in the repo's `rust-toolchain.toml`);
   - Linux desktop: `sudo apt install clang cmake ninja-build pkg-config libgtk-3-dev`;
     Android: the NDK; iOS/macOS: Xcode.
2. Get the code (the Rust crate needs the whole repository next to it):
   ```bash
   git clone https://github.com/atomicdata-dev/atomic-server
   cd atomic-server/packages/atomic_store_flutter/example
   ```
3. Run it (the first build compiles `atomic_lib`, about 10 minutes cold):
   ```bash
   flutter pub get
   flutter run -d linux     # or macos, an Android emulator, an iOS simulator
   ```

## Starting your own app from it

```bash
flutter create --platforms=linux,android,ios,macos my_app && cd my_app
```

Add to `pubspec.yaml`, with the paths pointing into your checkout (or `git:`
dependencies with `path:`, see the package README), plus `path_provider`:

```yaml
dependencies:
  atomic_store:
    path: ../atomic-server/packages/atomic_store
  atomic_store_flutter:
    path: ../atomic-server/packages/atomic_store_flutter
```

Then copy `lib/main.dart`. Persist `node.agentSecret` (see the comment in
`main.dart`) or every start is a new identity.
