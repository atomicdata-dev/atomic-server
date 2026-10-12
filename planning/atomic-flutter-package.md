# Shared Atomic Flutter package

- [x] Extract the actual Canvas settings and Devices widgets into `atomic_flutter`.
- [x] Define an app-independent backend contract; keep secrets and transports in the host.
- [x] Switch Canvas to the package through its existing public entry points.
- [x] Test phone layouts, drive operations, failures and disposal during load.
- [x] Keep optional server/account capabilities explicit.
- [x] Include drives recorded on the private home in the native drive list; preserve legacy entries.
- [ ] Extract the pairing screen and parser, with injectable QR scanner support.
- [ ] Extract secure account session storage and sign-in flow after agreeing the native/web API.
- [ ] Add a standalone example host and package publishing metadata.
- [ ] Verify Canvas and Audio pairing/account flows on physical devices.

This draft is the shared UI boundary, not yet a general Dart SDK for the Atomic
Rust API. The existing host adapters continue to own Iroh, Loro, file sync and
identity persistence.
