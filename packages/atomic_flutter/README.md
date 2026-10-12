# atomic_flutter

The account, device sync and drive dialog extracted from Atomic Canvas. Both
Canvas and Atomic Audio use `AgentSettingsDialog` with a host backend.

```dart
await AgentSettingsDialog.show(context, backend: settingsBackend);
```

Implement `AtomicSettingsBackend` using your Atomic client. The host owns
identity storage, native bindings, pairing, drive persistence and application
state transitions. The package owns the existing Canvas dialog and Devices UI.
Secrets are fetched only when Copy Secret is pressed. `servers`, `signIn` and
`signOut` are optional capabilities; their actions appear only when supplied.
`switchDrive` must persist selection and switch the host's project state before
returning. Failures must throw, not be swallowed by the host.

The package uses Flutter only, with no native bridge or app import. It is not
yet published on pub.dev. Consume via a Git dependency pinned to a revision,
with `path: packages/atomic_flutter`, or via a local path during development.

Canvas's adapter is `flutter/lib/atomic/settings_backend.dart`. Pairing and
secure sign-in remain host adapters in this first extraction. A future package
can extract those implementations without coupling this UI to a native ABI.

Run `flutter analyze` and `flutter test` in this directory.

## Hosted accounts

`AtomicAccountClient` implements the provider device-code flow, origin-bound
bearer sessions, account/device/hosting discovery, and AES-GCM assisted recovery.
It has no default provider and makes no request until called. The host owns
credential storage and must verify the recovered subject against the key before
installing it. Secrets are never part of an approval URL.

`AtomicAccountLinkDialog` handles approval and cancellation. Supply a URL launcher
and an installation callback. `AtomicSettingsBackend.signInWithAccount`,
`accountStatus`, `syncAccount`, and `useLocalProjects` expose this in the shared
user dialog. Existing manual-secret and peer-only hosts remain supported.

A provider session alone does not prove a workspace is synced. This package does
not implement Cloud Vault transport; hosts must connect their Atomic runtime to
the discovered Cloud Server or peer and verify received data.
