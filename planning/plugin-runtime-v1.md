# Plugin runtime v1: implementation contract

Status: implemented subset on `feat/plugin-model`, 2026-09-05. Follow
[plugin-model-review.md](plugin-model-review.md) for the remaining release and
bidirectional-sync work. A minimal public package/catalog format exists; compatibility certification and
connection upgrades are still open.

## One authoring path

Handwritten and generated JavaScript use the same exported `run` function,
manifest, planner and apply machinery. Server placement is automatic for declared
network operations or stored credentials. Browser code has no ambient I/O.
Unattended execution stays in atomic-server.

```js
export const manifest = {
  schemaVersion: 1,
  secrets: [],
  operations: [{
    id: 'list',
    method: 'GET',
    url: 'https://api.example.org/records',
    effect: 'read',
  }],
};

export function run(ctx) {
  const response = ctx.http({
    operation: 'list',
    method: 'GET',
    url: `https://api.example.org/records?page=${encodeURIComponent(ctx.cursor ?? '')}`,
  });
  if (response.status !== 200) throw new Error(`API returned ${response.status}`);
  // Parse the provider page, map existing schema subjects, and return Atomic
  // intents. Only return its next cursor after accounting for the entire page.
  return { intents: [], problems: [] };
}
```

The example is a contract illustration, not a tested provider integration.
Endpoints match exact origins and paths; query values can vary. Methods and
operation IDs must match. A POST query can declare `effect: 'read'`; the provider
must actually guarantee it is read-only. A declaration is not proof of that.
Declared writes cannot execute through preview fetch. Sync programs can now yield
external/Atomic/checkpoint effects through the generic durable session driver;
the host executes approved effects and returns receipts to the next sandbox call.
See `github-issues-pilot.md`. Scheduled bidirectional sync remains open.

Credentials use declared `{ name, origin, description? }` entries and opaque
`secret:<name>` handles in headers. The host checks both the declaration and the
stored secret's origin. URLs and bodies cannot carry secret handles. Public reads
need no credential. HTTP destination resolution is checked once and pinned; the
response is capped while being read. Redirects and ambient proxies are disabled.

Legacy manifests without a version retain credential-scoped GET/HEAD access.
Other methods require a version-one read declaration. Unknown fields or malformed
versioned declarations are rejected, rather than silently granting partial access.

## Review and unattended execution

- Manual run records keep the exact executed source.
- Auto-apply requires a reviewed run of the current source and retains that source
  snapshot. Editing the draft does not modify existing unattended execution.
- Old approvals without a source snapshot need renewed authorization.
- A schedule persists its claim before executing and its proposal before applying.
  Interrupted claims and pending proposals pause execution. This prevents blind
  replay; saved runs can resume completed effects from receipts. Effects without receipts
  remain uncertain and require reconciliation.
- Empty successful pages may checkpoint. Partial/blocked pages may not. Scheduled
  execution restores the most recent successful recorded cursor.
- A trigger preserves its pending proposal and pauses rather than overwriting it.
  Membership changes while paused still need a durable event queue/backfill design.

## Shared vocabulary

`createApp({ ..., rowClass: existingClassSubject })` binds a template to an
existing class. `ensureSchema` accepts `subject` on a property/class spec. Those
bindings are referenced, not copied or reconciled. Local schema creation remains
available for private experiments. Complete immutable schema releases, explicit
runtime vocabulary bindings and JSON Schema interoperability remain open.

## Release gates still to implement

- [x] Content-addressed source + manifest + schema identities + runtime-version package.
- [ ] Immutable snapshots of mutable schema dependencies.
- [ ] Connection instances, account scope approval and explicit upgrades.
- [ ] External intent journal with operation identities, receipts and reconciliation.
- [ ] Replay fixtures with independently checked expected provider behavior.
- [ ] Fault tests for pagination, rate limits, deletion, normalization, conflict,
      duplicate delivery and a lost response after a successful remote write.
- [ ] Real provider sandbox checks and honest object/direction coverage metadata.
- [x] Store discovery, explicit publication and independent draft creation.
- [ ] Support ownership, compatibility evidence and PR publishing.

LLM-generated code must pass the same gates as every other connector. A fixture
invented by the same generator is useful for iteration, but cannot establish API
compatibility on its own.

## Implemented host APIs

`publishPluginRelease` publishes an immutable package to this server's public
catalog. `approveExternalIntent` sends an explicitly approved operation with stable
run/intent IDs. Neither API is exposed inside the preview interpreter. External
receipts survive duplicate requests; uncertain outcomes are blocked, not retried.
`reconcileRecord` proposes field patches and conflicts; `acknowledgedBaseline`
advances only after actual normalized projections agree. Adapters still own the
provider mapping and durable baseline storage.

The store labels every entry Unverified. Creating a draft carries source and schema
bindings, not credentials or unattended approval. Publication is public; authoring
and approval alone do not publish a package.

## Recovery and durable reconciliation state

`inspectExternalOperation` returns the stored request, receipt and any resolution
for an authorized plugin instance. If an operator checks the provider and confirms
the original operation succeeded, `confirmExternalOperation` records that receipt
with evidence and the server-established actor/time. It never resends the request,
never overwrites an existing receipt, and does not assert automatic verification.
An absent receipt remains blocked until this confirmation; confirmed-not-applied
retry and provider-specific automated verification remain future work.

`readConnectionState` returns `{ revision, records, cursor }` for the instance.
Each remote identity maps to one local identity and an acknowledged projection.
`checkpointConnection` takes the expected revision, page acknowledgements and next
cursor. The server rejects stale revisions, divergent projections and rebinding;
it validates the whole page before persisting anything. Empty pages preserve
identity mappings. Explicit null projections retain tombstones. Callers must supply
actual normalized projections after verifying both sides; this API does not fetch
the provider. State and credentials remain private to the plugin instance.

## Default containment for app-owned data

Use the drive for authorization scope. Default app-owned tables and supporting
records beneath the app/plugin container, and rows beneath their table. The drive
root should contain the app entry, not every generated record. Preserve explicit
existing-table bindings and shared resources; references do not imply ownership
or relocation. Migrate old root-level records only with unambiguous provenance
and reviewed parent changes. Clockify now follows this rule; generated plugin
authoring guidance states it explicitly.
