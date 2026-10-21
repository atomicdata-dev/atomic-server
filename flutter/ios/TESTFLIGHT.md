# atomic.place TestFlight

App name: **atomic.place**. Bundle ID: **io.ontola.atomic**.
App Store Connect Apple ID: **6824840977**.
The Android application ID is the same. These are the main product's identities,
independent of Flutter or any future implementation.

`.github/workflows/flutter-testflight.yml` builds the renderer and Rust-backed
Flutter app on macOS. It supports manual runs and the initial release branch.
Without credentials it produces an unsigned iOS build. With all three
repository secrets below, it builds an IPA and uploads to TestFlight:

- `APP_STORE_CONNECT_KEY_ID`
- `APP_STORE_CONNECT_ISSUER_ID`
- `APP_STORE_CONNECT_PRIVATE_KEY` (the P8 contents)

Use an App Store Connect API key authorized to manage this app's signing. Keep
its P8 in the password manager; never commit it. `testflight.py` creates a
certificate and provisioning profile for the run and cleans up only those
resources afterwards. Other apps' certificates and profiles are untouched.

The version comes from pubspec.yaml; the monotonically increasing build number
comes from github.run_number. Keep the workflow identity when shipping later
builds, or override the numbering strategy to stay above the last Apple upload.

A successful upload still requires Apple processing and any export-compliance
answers before testers can install it. Verify these in App Store Connect.

The Flutter Rust crate vendors netdev 0.31 with a narrow iOS fix: its
SCNetworkInterface metadata calls are macOS-only. Unix interface enumeration
remains active on iOS. See `flutter/rust/vendor/netdev/ATOMIC_PATCH.md`. CI uses
`ATOMIC_CARGO_TARGET_DIR` to keep Cargokit's actual Rust artifacts in the cached
`flutter/rust/target` directory, including after a failed Xcode build.

Signing is not tied to GitHub. The same `testflight.py prepare DIR`, Flutter
IPA build, and `xcrun altool` upload commands in the workflow can run on another
macOS CI provider or locally. Preserve the Apple API key/issuer and bundle ID,
and keep build numbers above the last uploaded build. The P8 backup is needed;
GitHub does not reveal stored Actions secret values.

First upload: **1.0.0 (5)** on 2026-10-20, from commit
`d3f6c33826f98d3ac0a0d10edad6beafbf5151f8`, workflow run `39395781157`.
Apple processed it as VALID. The initial distribution is the owner's internal
TestFlight group, **Atomic Internal**.

This app contains third-party cryptography (TLS/QUIC, Ed25519, X25519 and
ChaCha-based encrypted storage/chat). It does not merely use Apple's OS crypto.
The build's export-compliance answer is scoped to this internal beta with no
French App Store distribution. Do not copy it blindly to a worldwide App Store
release: reassess the French declaration requirements before that release.
No permanent encryption exemption was added to Info.plist.
