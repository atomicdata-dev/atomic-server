# atomic.place first TestFlight release

- [x] Snapshot committed Flutter work in an isolated checkout; preserve live edits.
- [x] Use the product owner's permanent identity: atomic.place, io.ontola.atomic on iOS and Android.
- [x] Register io.ontola.atomic with Apple.
- [x] Create atomic.place in App Store Connect (Apple ID 6824840977).
- [x] Prepare iOS CI, signing and upload; fix missing RunnerTests Podfile target and minimum iOS version required by mobile_scanner.
- [x] Publish the prepared side branch to ontola/atomic-server after explicit user approval.
- [x] Configure the newly generated Atomic CI key for this repository's signing and upload steps.
- [x] Fix the iOS linker failure in netdev 0.31 with a Flutter-only vendored patch; verify an arm64 iOS dynamic-library link locally.
- [x] Create the Atomic Internal TestFlight group and add the owner's Apple account.
- [x] Run the iOS build, fix concrete failures, upload the signed IPA (1.0.0 build 5, run 39395781157).
- [x] Verify Apple processing (VALID), export-compliance status and internal availability (IN_BETA_TESTING); build 5 is in Atomic Internal.

Source snapshot: 1302adbfc, from claude/flutter-mobile-app-w8e9wz. Live uncommitted
work is not included. The release work is on codex/atomic-flutter-testflight.
The incorrectly registered legacy Apple identifier is unused; no build or app
record was published with it. Do not use it for this release.

## Android / Play continuation

- [x] Reuse permanent application ID `io.ontola.atomic` and the existing Atomic PKCS12 upload key.
- [x] Replace debug release signing with explicit release configuration; ignore local key files.
- [x] Add a signed arm64 AAB workflow and native 16 KB alignment verification.
- [x] Observe the user-created Play Console app, ID 4973792617288465041.
- [x] Complete the first signed Android CI build: 1.0.0 (1), run 39424359675, artifact 12266865399. All six native arm64 libraries pass 16 KB alignment checks.
- [x] Upload and publish signed bundle 1.0.0 (1) to Play internal testing (20 October 2026, 16:25 Europe/Amsterdam).
- [ ] Save Atomic Internal tester access for the owner after confirmation of the exact email addresses.

Play Console developer: 6245351578543299123. Android-only changes are excluded
from the iOS push trigger so subsequent Android releases do not also upload an IPA.

First bundle SHA-256: `82a8d7fbff6caff2929c266a1a9483e8893943e9ecb209c2e03976eb9717ba89`.
Play Console reports Available to internal testers. Tester selection remains pending.
Opt-in: https://play.google.com/apps/internaltest/4700697182889756841
The approved play-ci serviceaccount authenticated, but the reviews API returns 403;
automated publishing permissions have not yet been verified or configured.
