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

### Sync / Pairing

Devices sync via [Iroh](https://iroh.computer) (QUIC peer-to-peer, works through NAT).

- Open Settings > **Pair with QR Code**
- Device A shows its QR code, Device B scans it (or vice versa)
- Sync is bidirectional — both devices exchange data regardless of who initiates

NodeIDs are persistent (stored in the local DB), so a QR code stays valid across app restarts.

## Architecture

The Dart client code in `lib/atomic/` (`AtomicClient`, `session.dart`, FRB bridge) is a general-purpose Atomic Data SDK wrapping `atomic_lib` via `flutter_rust_bridge`. Once the API stabilizes, it should be extracted to `atomic-server/dart/` (or `sdk/dart/`) as a reusable Dart package, keeping this app as a thin UI layer on top.

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
