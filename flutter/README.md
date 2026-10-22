# Atomic

The Atomic app for Android, iOS and the web: a local-first Flutter client for Atomic Data that signs in, syncs with an Atomic Server and pairs with other devices.

## Development

This project uses [mise](https://mise.jdx.dev/) to manage the Flutter SDK (Flutter 3.44+, Dart 3.12 — see `.mise.toml`).

A `Makefile` wraps `dev.sh` which sets up a FIFO pipe so you can trigger hot reload **from any terminal tab** — no need to switch focus or type into the running process.

### Starting dev servers

Run each device in a separate terminal (they share `build/`, so don't start them simultaneously):

```bash
# Terminal 1
make tablet     # Samsung SM X810 tablet

# Terminal 2 (after tablet finishes building)
make phone      # Pixel phone (456cb10b)

make web        # Chrome (separate terminal)
```

### Logs

Output is captured to `logs/<target>.log` (truncated on each launch):

```bash
grep "error" logs/tablet.log
grep "iroh" logs/phone.log
```

### Hot reload (from any terminal)

```bash
make reload-tablet    # Hot reload
make restart-tablet   # Hot restart
make reload-all       # Reload all running targets
make restart-all
```

### Other

```bash
make analyze    # Static analysis
```

To update the Android device IDs, edit `dev.sh` (`ANDROID1_ID` = tablet, `ANDROID2_ID` = phone).

### Building the Android app

The Rust library is built by cargokit (`rust_builder/cargokit`) during the Gradle build, with the toolchain pinned in the repo's `rust-toolchain.toml` (cargokit used to use rustup's `stable`: std 1.95 has no `File::try_lock` on Android, so redb's file lock silently did nothing). rustup installs that toolchain and the Android targets itself on first use; to do it up front:

```bash
# from the repo root, so rustup picks up rust-toolchain.toml
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
```

Debug builds keep every ABI (x86_64 emulators). Release and profile APKs are **arm64-v8a only** (the other ABIs' libraries are excluded from the package, `android/app/build.gradle`). Also pass the platform so cargokit builds only that Rust target:

```bash
flutter build apk --release --target-platform android-arm64
```

For another ABI, name it and lift the exclusion:

```bash
flutter build apk --release --target-platform android-arm,android-x64 \
  --android-project-arg=atomic.allAbis=true
```

(`--split-per-abi` also works together with `atomic.allAbis`.)

To put a release build on your own devices, keeping their data:

```bash
scripts/deploy_release.sh SERIAL...          # adb devices -l for the serials
scripts/deploy_release.sh --no-build SERIAL  # the APK that is there
```

It builds the arm64 release APK (cargokit builds the Rust library with `--release`: fat LTO, one codegen unit), refuses an APK with `kernel_blob.bin` (a debug build), installs with `adb install -r`, starts the app and checks it is not `DEBUGGABLE`. Release builds are signed with the debug key, so they replace a debug install from the same machine in place; a device with the app signed by another key fails the install, and the script never uninstalls (that would wipe the store and identity). A debug build is much slower: on the Tablet_A35 emulator a cold start took 1.7 s to the painted home in debug and 0.95 s in a profile build, each Home list read 240 ms against 11-18 ms (`scripts/perf_android.sh --only cold,scroll`).

### Sync / Pairing

Devices sync via [Iroh](https://iroh.computer) (QUIC peer-to-peer, works through NAT).

- Open Settings > **Pair with QR Code**
- Device A shows its QR code, Device B scans it (or vice versa)
- Sync is bidirectional — both devices exchange data regardless of who initiates

NodeIDs are persistent (stored in the local DB), so a QR code stays valid across app restarts.

## Architecture

Three layers, each usable without the next:

1. **The bridge** (`rust/src/api/`, generated glue in `lib/src/rust/`): thin
   `flutter_rust_bridge` bindings over `atomic_lib`.
   - `api/simple/` holds the older flat functions by domain: `agent`, `drive`,
     `resource`, `files`, `store` (open/flush/stats), `sync` (server) and
     `peers` (Iroh). Many return JSON strings and `String` errors; they stay
     as they are until a screen is moved off them.
   - `api/error.rs` + `api/resources.rs` are the typed generic API: `AtomicError`
     (`kind` + `message`), `AtomicValue`, `ResourceData`,
     `get_resource_data`, `save_resource_changes`, `create_resource_with_values`,
     `search_resources`, `get_child_subjects`, `wait_for_resource_event`.
     New bridge functions should look like these.
   - `api/assistant.rs` holds the app-shaped functions (home lists, chats).
2. **`packages/atomic_store`**: a pure Dart `Store`/`Resource` that rhymes with
   `@tomic/lib` (see its README), over an injectable `StoreBackend`. The app's
   backend is `lib/atomic/bridge_store_backend.dart`.
3. **App-specific APIs**: `AssistantApi` (`packages/atomic_chat`, implemented
   in `lib/assistant/atomic_assistant_api.dart`) for the screens, and
   `AtomicClient` (`lib/atomic/`) for sign-in, servers and sync.

The generated bridge files are checked in and CI regenerates them with the
pinned codegen (`flutter_rust_bridge_codegen` 2.12.0, same as the
`flutter_rust_bridge` dependency) and fails on any diff:

```bash
cd flutter && flutter_rust_bridge_codegen generate
```

Enums with fields would make the codegen require `freezed`; use a struct plus
a unit enum instead (`AtomicError`/`ErrorKind`, `AtomicValue`/`Datatype`).

### Next step: no globals

The bridge still holds one open store and one active agent and drive per
process (`api/simple/state.rs`, `Db::set_active_drive`). `atomic_store` takes
its drive explicitly, but a second `Store` over the bridge shares the
signing agent and the open database. Removing that means an opaque store
handle (`#[frb(opaque)] AtomicStore`) that owns the `Db`, agent and active
drive, with the functions above as its methods, and `BridgeStoreBackend`
holding the handle. The sync, peer and assistant functions read the global
store too (`db()`), so they move along with it; it is a change of its own.

## App identity

The app is **atomic.place**. Its permanent iOS bundle identifier and Android
application ID are both `io.ontola.atomic`, following the `io.ontola.*` naming
used by the other Ontola apps. This is the main app, not a separate Flutter
edition. The product owner approved replacing the development identifiers on
2026-10-20 before the first store release.

The Dart package is `atomic_app` and the Rust crate is `atomic_flutter_rust`.
Android's internal Kotlin namespace remains `com.ontola.atomiccanvas_flutter`;
it is not the installed application ID. Existing development installs with the
old application IDs remain separate and their local data is not migrated.
