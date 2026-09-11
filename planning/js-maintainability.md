# JavaScript maintainability follow-ups

> **Status: in progress, 2026-09-11.** PluginPage subscriptions are implemented;
> diagnostic collectors are extracted; Store coordination remains. Baseline: `develop` at `6045bff3a`, following PRs
> [#1450](https://github.com/ontola/atomic-server/pull/1450) and
> [#1451](https://github.com/ontola/atomic-server/pull/1451).

## Existing boundaries to preserve

- `Resource` is a stable mutation handle. `useResourceSnapshot` exposes immutable
  read status; property hooks subscribe to rendered values.
- `Store.getSaveState(resource)` / `useSaveState(resource)` expose immutable save
  status independently of read readiness. A queued offline edit can remain readable.
- `ScheduledSave` already owns debounce slots, cancellation and flushing.
  `Store.createSaveScheduler` connects it to pending-work accounting.
- Local JSON and Loro snapshots are hydrated before publication. Loro remains
  authoritative; the outbox remains the single durable outbound queue.
- E2E failures already attach bounded resource/save metadata and recent WebSocket
  frame metadata before context teardown. Payloads and resource values are excluded.

This plan owns the next implementation slices. The architectural constraints remain
in [unified-data-layer.md](./unified-data-layer.md),
[react-compiler-resource-proxy.md](./react-compiler-resource-proxy.md), and
[unify-resource-dirty-signals.md](./unify-resource-dirty-signals.md).

## 1. PluginPage subscriptions

Start in [PluginPage.tsx](../browser/data-browser/src/views/Plugin/PluginPage.tsx).
Version, author, description and JSON schema now use property hooks; Save uses
`useSaveState`. Parent is read when uninstall starts, before destruction. The
production regression reproduced valid config leaving Save disabled on the
previous implementation. JSONEditor keeps its mounted draft; metadata changes
do not reset it. Save enables for valid dirty state or a new config edit since the previous Save,
including a later offline draft. In-flight and scheduled saves stay disabled;
a queued/failed write alone does not enable another Save. A separate attempted real plugin-update regression still showed the old version
on the updating client after refresh. Manifest metadata is GET enrichment; its
interaction with Loro hydration and cross-client invalidation needs investigation
in a separate change. The retained test mutates the mounted client resource and
verifies metadata subscriptions and preservation of an active config draft.

- [x] Reproduce a stale render or Save-button transition while retaining the same
  Resource object. Use the cheapest failing layer; verify compiler behavior in a
  production Playwright build when a helper/unit test cannot exercise it.
- [x] Replace rendered scalar reads with `useString` and structured reads with
  `useValue`; use the existing save-state subscription for persistence status.
- [x] Define the Save-button policy explicitly: invalid JSON cannot save; in-flight
  saving cannot submit twice; queued/offline/failed writes remain distinguishable
  from new unsaved config. Do not assume every non-idle state should enable Save.
- [x] Check `JSONEditor`'s `initialValue` behavior before changing schema/config
  subscriptions. A remote update must not reset an active local edit.
- [x] Verify client metadata updates, valid/invalid config, save completion and
  repeated offline saves. Keep uninstall/update permissions unchanged.
- [ ] Follow up on remote manifest metadata refresh in `react-compiler-resource-proxy.md`;
  the real Update flow did not display its new version on the updating client.

Acceptance: the reproduced failure passes without a compiler opt-out or replacing
Resource identity. Limit the PR to this flow; event-handler reads need not become
subscriptions unless they are demonstrably stale.

## 2. E2E diagnostic collectors

[fixtures.ts](../browser/e2e/tests/fixtures.ts) now orchestrates context interception,
attachments and teardown. `DiagnosticCollector` and `TransportCollector` own
matching and observation with idempotent lifecycle methods.
[failure-state.ts](../browser/e2e/tests/failure-state.ts) already separates the
browser-side state snapshot. Extract the remaining collectors without changing
which diagnostics fail a test.

- [x] Extract console/error expectations and WebSocket metadata into independent
  collectors with explicit `start`, `snapshot`, and `dispose` lifecycles.
- [x] Let the fixture wire collectors to existing/new contexts, attach evidence,
  restore `browser.newContext`, and close only contexts it owns.
- [x] Make start/dispose idempotent and detach page, context **and socket** listeners.
  Preserve evidence collected before a page closes; tolerate crashed pages.
- [x] Preserve limits: at most five live pages sampled, two seconds per state read,
  50 relevant resources, 50 property keys per resource, 20 commits and 30 frame
  metadata records per page. Keep payloads, resource values and secrets excluded.
- [x] Exercise unexpected/missing/excess diagnostics, multiple contexts, repeated
  start/dispose, closed pages and bounded attachments. Keep one real WebSocket
  check; mocked routing alone did not emit the transport events being tested.

Acceptance: current diagnostic self-checks and attachment inspection pass; teardown
cannot replace the original failure with a collector error or leak into the next test.

Validation: all 14 diagnostic/collector checks pass with zero retries. Inspected
JSON attachments from real open and closed WebSocket pages: frame metadata is
retained and test payloads are absent. E2E typecheck and lint pass. The full
production suite will validate this together with the Store coordinator slice.

## 3. Extract Store save-status coordination

[store.ts](../browser/lib/src/store.ts) still owns scheduling integration, snapshot
caching and save-state subscriptions alongside loading, hydration, sync and logging.
Start with that small responsibility; do not split the entire Store in one PR.

- [ ] Inventory `scheduledByResource`, `saveSnapshots`, `createSaveScheduler`,
  `getSaveState` and `subscribeSaveState`, plus their event inputs and cleanup.
- [ ] Move their implementation behind an internal coordinator. Retain existing
  Store methods as delegates so React and downstream callers do not change.
- [ ] Inject narrow access to outbox entries, connection state and pending-work
  notifications. The coordinator must not fetch resources, sign commits, drain the
  outbox or keep a second copy of persistence truth.
- [ ] Preserve Resource identity through `_new:` → DID renaming, cached immutable
  snapshot identity, overlapping owners and exact in-flight accounting.
- [ ] Keep legacy global start/finish methods compatible. Deletion uses them for
  non-save writes; removing them needs its own caller audit.
- [ ] Run scheduler/store regressions, types and compiled inspector/table/offline
  flows. Test that disposing one observer cannot cancel another owner's save.

Acceptance: public APIs and behavior remain unchanged, the extracted module can
be tested with narrow dependencies, and no circular Store import is introduced.
Hydration, sync and commit-log extraction remain future candidates requiring their
own evidence and boundary review.

## Delivery and verification

Ship in order: PluginPage, collectors, then Store coordination, as separate PRs.
Record each reproduction and focused validation; run the full production E2E suite
for shared lifecycle changes. Update [TESTING_COVERAGE.md](../TESTING_COVERAGE.md)
when coverage changes. Local passing tests, hosted CI and deployment are separate
results—do not infer one from another.

The prior implementation's local baseline was 450 library tests, 850 app tests,
and 209 Chromium tests passed with eight skips (including external Cloud Vault).
Those counts are historical evidence, not permanent acceptance thresholds or proof
of CI success. Remove this plan when all three slices are complete and place any
remaining follow-ups in their owning plans.
