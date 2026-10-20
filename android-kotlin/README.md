# atomic.place for Android, native Kotlin

A Kotlin / Jetpack Compose fork of the Flutter app (`../flutter`). Same Rust
core (`atomic_lib::host`), native UI. Plan and parity checklist:
`../planning/android-kotlin.md`. Applicationid `place.atomic.app.kotlin`, so it
installs next to the Flutter app.

```
android-kotlin/
  rust/   crate atomic_kotlin_rust (cdylib, UniFFI proc-macro bindings), own [workspace]
  app/    Gradle module: Compose UI, runs cargo-ndk + uniffi-bindgen before the build
```

## Toolchain (reproducible, as set up in the cloud container)

Needs: JDK 17+, Gradle 8.14 (the wrapper downloads it), Rust (see
`../rust-toolchain.toml`), `unzip`, `curl`. The SDK lives outside the repo.

```sh
# 1. Android SDK: cmdline-tools, platform 35, build-tools 35, platform-tools, NDK 27
export ANDROID_HOME=/opt/android          # or ~/android
mkdir -p $ANDROID_HOME/cmdline-tools
curl -sSLO https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip
unzip -q commandlinetools-linux-13114758_latest.zip -d /tmp/clt
mv /tmp/clt/cmdline-tools $ANDROID_HOME/cmdline-tools/latest
yes | $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager --licenses
$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager \
  "platforms;android-35" "build-tools;35.0.0" "platform-tools" "ndk;27.2.12479018"

# 2. Rust targets and cargo-ndk
rustup target add aarch64-linux-android x86_64-linux-android
cargo install cargo-ndk --locked

# 3. Tell Gradle where things are (local.properties is gitignored)
echo "sdk.dir=$ANDROID_HOME" > android-kotlin/local.properties
```

`ANDROID_NDK_HOME` is derived by the Gradle task from `$ANDROID_HOME/ndk/27.2.12479018`.
There is no `/dev/kvm` in the cloud container, so no emulator runs there; UI is
checked with JVM screenshot tests (Roborazzi) instead, see below.

## Build and test

```sh
cd android-kotlin
(cd rust && cargo test)             # host-facing Rust, runs on the Linux host
./gradlew testDebugUnitTest         # Kotlin unit tests + Home screenshot tests
./gradlew assembleDebug             # cargo-ndk (arm64-v8a, x86_64) + uniffi-bindgen + APK
```

