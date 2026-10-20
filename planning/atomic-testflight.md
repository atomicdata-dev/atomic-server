# atomic.place first TestFlight release

- [x] Snapshot committed Flutter work in an isolated checkout; preserve live edits.
- [x] Use the product owner's permanent identity: atomic.place, io.ontola.atomic on iOS and Android.
- [x] Register io.ontola.atomic with Apple.
- [x] Create atomic.place in App Store Connect (Apple ID 6824840977).
- [x] Prepare iOS CI, signing and upload; fix missing RunnerTests Podfile target and minimum iOS version required by mobile_scanner.
- [x] Publish the prepared side branch to ontola/atomic-server after explicit user approval.
- [x] Configure the newly generated Atomic CI key for this repository's signing and upload steps.
- [ ] Run the iOS build, fix concrete failures, upload the signed IPA.
- [ ] Verify Apple processing, export-compliance status and availability to internal testers.

Source snapshot: 1302adbfc, from claude/flutter-mobile-app-w8e9wz. Live uncommitted
work is not included. The release work is on codex/atomic-flutter-testflight.
The incorrectly registered legacy Apple identifier is unused; no build or app
record was published with it. Do not use it for this release.
