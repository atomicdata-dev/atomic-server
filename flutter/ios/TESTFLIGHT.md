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
