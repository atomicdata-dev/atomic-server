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

## First build

Version 1.0.0 (1), CI run 39424359675, artifact `atomic-place-aab`
(ID 12266865399), built and verified successfully. Manifest identity is
`io.ontola.atomic`, label `atomic.place`, arm64-v8a only.

SHA-256: `82a8d7fbff6caff2929c266a1a9483e8893943e9ecb209c2e03976eb9717ba89`.

Uploaded and published to internal testing on 20 October 2026 at 16:25
Europe/Amsterdam. Play Console reports Available to internal testers.
Tester-list selection is pending confirmation of the owner account addresses.
Opt-in: https://play.google.com/apps/internaltest/4700697182889756841

Google temporarily displays `io.ontola.atomic (unreviewed)` until the store
setup and app review are complete.

App dashboard:
https://play.google.com/console/u/1/developers/6245351578543299123/app/4973792617288465041/app-dashboard
