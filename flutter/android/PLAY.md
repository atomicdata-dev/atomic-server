# atomic.place on Google Play

Permanent application ID: `io.ontola.atomic`. Display name: `atomic.place`.
The Flutter app stays on `codex/atomic-flutter-testflight` while development continues.

Run **Atomic Flutter Android** on that branch to produce `atomic-place-aab`.
The workflow builds the embedded renderer, compiles the arm64 Rust/Flutter app,
uses the existing Atomic PKCS12 upload key, and checks every native ELF library
for 16 KB page alignment. The workflow run number is the Android version code.
Initial distribution is Google Play **internal testing**.

Signing uses existing repository secrets `ANDROID_KEYSTORE_BASE64`,
`ANDROID_KEYSTORE_PASSWORD`, and `ANDROID_KEY_ALIAS`. PKCS12 uses the store
password for the private key too. No signing material is committed or included
in artifacts. Release builds no longer fall back to the debug key.

For releases outside GitHub, restore the same upload keystore from its backup,
write ignored `android/key.properties` with storeFile, storePassword, keyAlias,
and keyPassword, build the renderer, then run:

```sh
flutter pub get
flutter build appbundle --release --target-platform android-arm64 --build-number=<unused-increasing-code>
```

Upload `build/app/outputs/bundle/release/app-release.aab` to Play Console.
