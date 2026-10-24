# atomic_flutter

The user panel (identity, workspaces, devices, servers) extracted from the Atomic app. Both
the app and Atomic Audio use `AtomicUserPanel` with a host backend.

```dart
await showAtomicUserDialog(context, backend: settingsBackend);
```

Implement `AtomicSettingsBackend` using your Atomic client. The host owns
identity storage, native bindings, pairing, drive persistence and application
state transitions. The package owns the panel and Devices UI: the app shows `AtomicUserPanel` as
a page, other apps open it with `showAtomicUserDialog`. Secrets are fetched only
when asked for. `servers`, `signOut`, `signInWithSecret`, `inviteLink` and
`watchActiveAgent` are optional capabilities; their rows appear only when
supplied. The app adds what only it has through the panel's builders (account,
this device, profile page).
`switchDrive` must persist selection and switch the host's project state before
returning. Failures must throw, not be swallowed by the host.

The package uses Flutter only, with no native bridge or app import. It is not
yet published on pub.dev. Consume via a Git dependency pinned to a revision,
with `path: packages/atomic_flutter`, or via a local path during development.

The app's adapter is `flutter/lib/atomic/settings_backend.dart`. Pairing and
secure sign-in remain host adapters in this first extraction. A future package
can extract those implementations without coupling this UI to a native ABI.

`AppColors` (`context.appColors`) holds the color tokens of the Atomic apps as
a `ThemeExtension`; register `AppColors.light` or `AppColors.dark` in the
theme. The assistant screens built on this package live in
`packages/atomic_chat`.

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
