# Prepare 0.41.0-beta.6

Status: user authorized beta.6 publication after the passing full local E2E run on 2026-09-09. Publish the desktop/server beta using the existing workflow; npm automation in #1355 remains separate unfinished work.

## Prepared

- [x] Isolated PR branch from develop; beta.5 is the last prerelease.
- [x] Bump all 17 version sites with scripts/bump-version.mjs.
- [x] Regenerate Rust and pnpm lockfiles without dependency upgrades.
- [x] Add recovery, discovery, per-drive sync and security notes under UNRELEASED.
- [x] Configure npm Trusted Publishing for lib, react, svelte, cli and create-template: ontola/atomic-server, release.yml, direct publishing.

## Local E2E evidence

The full 201-case Playwright run passed: **195 passed, 6 existing skips, zero failures**. Library tests passed (392 tests), as did frontend typecheck, production frontend build and native server build. See [detailed results](beta6-e2e-results.md) for fixes, artifacts and scope. The user approved release on this local E2E evidence. CI and device acceptance below remain explicitly unverified.

## Follow-up validation and publishing work

- [ ] Green full CI on the final release commit, including downstream atomic-saas compatibility. Latest develop pipeline was still running when this PR was prepared.
- [ ] Finish and merge #1355; plugin and edit-mode still need their first npm publication and Trusted Publisher setup. Do not assume OIDC can publish an unconfigured package.
- [ ] Verify a clean desktop install and an upgrade from beta.5 against staging: restore with the existing agent, discover or enter the staging server, fetch both private and shared drives, and compare actual content.
- [ ] Verify live edits in both directions after fetching; account linking and a sync acknowledgement alone are insufficient.
- [ ] Verify recovery-code secret reveal and additional passkey registration on mobile.
- [ ] Test waiting for an offline source, then turning that source on with the discovery screen open.
- [ ] Confirm staging runs compatible SaaS #54/#55 and server code; merging is not deployment evidence.
- [ ] Review security compatibility: signed plugin-list/UI requests, node-bound Iroh auth and loopback binding for desktop/Android.
- [x] Move UNRELEASED notes to a dated beta.6 section after release approval.
- [ ] After approval, tag the reviewed commit; verify desktop artifacts, crate and npm beta versions, and updater metadata.

## Draft release highlights

Beta.6 focuses on restoring an existing workspace onto another device, clearer per-drive cloud status, recovery-code and passkey options, collaboration consistency, incremental backups, and authentication/sync security fixes.

Known limits: #1357 remains excluded at the user's request. First-publish npm setup is incomplete for plugin and edit-mode. Signed history envelopes do not yet travel through bulk sync or Cloud Vault.

The user subsequently authorized tagging and publishing beta.6. Pre-release tags do not deploy production.
