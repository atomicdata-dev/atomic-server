# @tomic/service-ui

Shared Cloud Vault / Cloud Server presentation for the SaaS portal and Sync page.
Owns product copy, service icons, row/body/title/description layout, group surface,
and primary action styling. Import `@tomic/service-ui/styles.css` once per host.
Hosts can map `--service-accent`, `--service-muted`, `--service-neutral` and
`--service-text` to their theme.

This package has no account, billing, routing, or cryptography dependencies.
Hosts supply real state and actions. The portal must link to Sync for operations
requiring the local drive and keys; it must not pretend to run a local backup.
Canonical copy lives here instead of separate product-name constants per app.

Build before building either consumer: `pnpm --dir browser/service-ui build`.
The workspace build does this in dependency order. The paired SaaS checkout uses
a file dependency, like its existing `@tomic/lib` and `@tomic/edit-mode` dependencies.
