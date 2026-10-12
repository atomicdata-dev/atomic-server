# Flutter account linking

Status: implemented draft, production acceptance pending.

- [x] Provider-neutral device-link client in atomic_flutter; explicit HTTPS origin and no HTTP redirects.
- [x] Shared browser approval dialog with cancellable polling and host-owned credential installation.
- [x] AES-GCM assisted identity recovery compatible with browser envelope-v2; never overwrites a backup.
- [x] Discover account devices and Cloud Server enrollments.
- [x] Native live File updates request missing BLAKE3 bytes after admission and persistence.
- [x] Atomic Audio consumes the package with separate account directories and canonical identifier migration.
- [x] Mock protocol, independent AES fixture, cancellation, profile isolation and real native peer sync checks.
- [ ] Live atomic.place account creation/approval and cross-app data check. Browser permission currently blocks that origin.
- [ ] Cloud Vault transport in Flutter. This first connection supports enrolled Cloud Servers and reachable peer devices; it does not implement encrypted Vault object storage.
- [ ] Hot identity switching. Audio currently stages the recovered profile and requires restart so existing native peers never change identity underneath a running task.
