# Integration maintenance

Each provider lives in its own directory and ships a bundled ES module. The
runtime, permissions, reconciliation and recovery stay shared. Packages remain
experimental until their advertised capabilities have current live evidence.

Named actions, automation permissions, recovery and MCP setup are documented in
[ACTIONS.md](ACTIONS.md). The MCP stdio protocol test runs in the JS CI gate.

## One certification command

From the repository root:

```sh
node integrations/tooling/certify.mjs
```

Or from `browser`: `pnpm certify:integrations`.
This discovers every integration with a `package.json`, validates required
metadata/files, checks the committed bundle against a fresh build, typechecks,
runs fixture tests, and runs exact named Rust tests through QuickJS/WASM.
It fails if a requested test matches nothing. It never rebuilds the shipped file
in place to make a reproducibility failure disappear.

Options: `--integration notion`, `--layer js|sandbox|all`, and `--output /path`.
Default output: `artifacts/integration-certification/report.json` plus logs and
Vitest JSON. Use separate output directories for concurrent runs. A report is
marked running until finished; failed validation replaces old successful evidence.

A passing report certifies only its selected offline layer. Capabilities are
labelled **declaredCapabilities**, not individually verified promises. `live` is
always `not-run`: existing live-test environment switches are stripped. Missing
credentials and skipped tests never count as successful live verification.
The report binds evidence to the shipped bundle hash and package version.
Do not infer compatibility of a later release from an older report.

CI's JS gate discovers all providers. Rust CI mounts the complete integration
folder so compiled sandbox tests can include shipped bundles and manifest
fixtures. `dagger call integration-certification-report export --path ./report`
exports the JS-layer evidence. The full local command includes sandbox evidence;
CI's exported JS report deliberately does not claim its separate Rust gate ran.

## Adding or changing an integration

1. Supply `plugin.ts`, reproducible `plugin.js`, `tsconfig.json`,
   `vitest.config.ts`, README and `atomicCertification` in `package.json`.
2. Metadata identifies owner, support tier, pinned API version, supported scope
   and fully qualified Rust sandbox test names. A new package without metadata
   fails CI rather than silently escaping it.
3. Reproduce provider bugs with synthetic or scrubbed fixtures. Mock network
   replies, not the permission checks or execution engine. Include independent
   edits, conflicts, pagination, missing data and uncertain-write behavior.
4. Run the full certification command. Test installation and actual UI behavior
   when changing browser packaging; mapping tests alone cannot establish that.
5. Review changes to permissions, mappings and checkpoint formats. Existing
   connections stay pinned; an upgrade must preserve their bindings and pending
   effects. Code rollback is not reversal of remote writes.
6. Run bounded live checks in a dedicated vendor test account before promoting
   supported capabilities. Never use customer data as published fixtures.

LLM-generated contributions use exactly this path. An agent may propose a repair
and tests; passing tests do not authorize production permissions or publication.

## Store evidence and upgrades

After the full offline run, generate the repository evidence asset:

```sh
node integrations/tooling/publish-evidence.mjs artifacts/integration-certification/report.json
```

This writes `integrations/evidence.json` locally; it does not publish a release.
The command rejects partial, failed, stale or mismatched reports and requires
every current provider sandbox test. Review and commit the asset with the bundle.
The two bundled store cards expose these results on demand, checking the actual
shipped source hash before showing owner, version, date and check count. Results
older than 30 days are labelled. Third-party catalog entries remain unverified.
These results contain no live-provider certification or per-capability claims.

The GitHub sandbox regression exercises a compatible code-only upgrade with
existing bindings and no duplicate writes. An unresolved approved effect blocks
replacement by an upgrade or rollback and resumes against its original release.
Changed mapping/checkpoint formats still need explicit migration tests.

## Remaining maintenance work

- Dedicated vendor sandbox accounts and a separately authorized live-test runner
  with fixture ownership, budgets, cleanup and secret isolation. Current manual
  live checks are recorded in planning, not fabricated as CI certificates.
  [The bounded run contract](./LIVE_TESTING.md) defines scope and cleanup; it is
  not yet an automated runner.
- Capability-to-test evidence mapping and verified third-party evidence delivery.
- Mapping/checkpoint migration tests and staged release rollout.
- Health monitoring, provider-change alerts and ownership escalation.
- Reusable provider fixture builders and UI installation coverage for both pilots.

No recurring live jobs or automatic releases are enabled by this command.

Shared provider sign-in supports direct and managed deployments; see
[authorization service setup](AUTHORIZATION.md) for the common FOSS transport,
per-server provisioning, credential handling and current limits.
