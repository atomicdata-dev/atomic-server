# Shared import identity

- [x] Shared lookup rejects ambiguous identities. Plugins use the immediate parent;
  JSON-AD preserves its import-root subtree namespace for nested references.
- [x] Database write guard serializes duplicate identity claims on this server.
- [x] Shared sandbox JS mapper emits standard proposals, resolves local links,
  preserves last-source baselines, detects local/source conflicts and unchanged rows.
- [x] Guard baseline transitions at commit time against stale approvals/local edits.
- [x] Migrate MT940 and Clockify; adopt legacy identities without overwriting edits.
- [x] Unit, real-store concurrency, runtime and browser acceptance; update evidence.
- [x] Lost-receipt injection after a saved Clockify support record; retry creates
  only missing records and preserves final DID links.
- [x] Durable setup-step identities for MT940 importer/table/view, with unit
  coverage for lost receipts and failed queries.
- [x] Process-abort injection proves acknowledged native imports survive reopening
  redb. Import writes flush before acknowledging.
- [x] Shared schema orphan recovery and opt-in resumable table installation;
  Clockify resumes its draft and reuses saved setup resources.
- [x] Duplicate-source review links both records and blocks Apply. This is
  inspection, not cross-node merge or reference repair.
- [x] Preserve independently imported duplicates through bulk and live replica
  persistence. Snapshots, projections and indexes commit together; failures are
  propagated instead of acknowledging invisible records. Test both arrival orders
  and replay, while retaining uniqueness checks for new authored imports.
- [x] Signed primary-record decisions, comparison UI, stale review rejection,
  deterministic replay and re-review for changed/unseen copies or competing choices.
- [x] Sync bindings follow reviewed primaries, preserve their original baseline
  and previous-subject mapping, and advance revision to invalidate old approvals.
- [x] Original records, signed histories and existing links remain intact; retained
  record pages link to the primary. Current bundled importers use the decision.
- [x] Reviewed field-by-field consolidation with native validation.
- [x] Reviewed typed application-reference updates within the current drive.
- [ ] Cross-drive/reference discovery at larger scale, explicit retirement of
  retained copies, and cross-version primary-deletion handling.
- [x] Import conflict review shows local/source values, supports keeping local or
  using source, then requires a fresh preview. Commit guards reject stale reviews.
  MT940 append-only changes remain blocked for bank-reference review.
- [x] GitHub/Notion atomic writes claim provider-qualified native localIds and
  migrate unchanged legacy rows through the normal reviewed sync step. Existing
  sync baselines, provider IDs and connection bindings stay authoritative.
- [x] Clockify installations expose a replacement-code review and update/pin
  flow. JSON configuration and stored secrets are retained; custom code replacement
  is explicit. Browser test verifies replacement and preserved configuration.
- [ ] User adoption of updates to their existing live integrations (no silent update).

Scope: one authoritative AtomicServer. Independent offline peers cannot enforce
cross-node uniqueness without coordination; sync collision resolution is separate.
Keep parsing/provider-specific mapping in plugins, identity and conflict policy
in shared code. No new execution system and no silent upgrades of installed code.

## Resolution policy

A reviewed primary-record decision resolves the source identity without destroying
or rewriting either original. `importResolution` stores the selected subject,
reviewed member snapshots and superseded decision IDs. Every copy must still match
at commit time. Changing the primary's values later is allowed; a changed retained
copy, unseen member or competing decision blocks future imports until re-reviewed.

Existing graph links remain unchanged unless explicitly reviewed. Their
pages point to the primary, and future imports plus host-owned connection bindings
use it. Explicit field choices now consolidate reviewed application values into the primary. It is not a graph-wide reference rewrite.
Do not present this as deleting/physically merging duplicate resources. Ordinary
signed deletion or identity changes of a primary are refused; broader retirement
and older-peer deletion handling still need design and tests.

Native tests exercise independent stores, both arrival orders, replay and changed
offline values. The browser test forks independent Loro histories, sends them via
authenticated SYNC_PUSH, compares real records and saves a signed decision. This
is real browser/server transport, but not two isolated OS-process importers.

## Recovery constraints

Schema recovery uses native localIds for new terms; older unlinked terms without
those identities are not automatically adopted. Table setup requires a stable
installationKey and identical input; ordinary manual table creation stays separate.
The Clockify draft is scoped to the agent and retains its server-stored credential.
Ontology attachment appends native Loro list items instead of replacing the list.

Import baseline validation checks the submitted causal state as well as the merged
state: a losing baseline operation must not disguise a stale source-value write.
Writes to identified imports flush redb before receipts; this adds per-write I/O
and has not been benchmarked.

## Replica persistence boundary

Only already-admitted replica writes use `persist_replicated_resource`. Ordinary
`add_resource_opts` and signed commits retain their identity guards. Replica
persistence must not enforce a single-server creation constraint against valid
independent histories: doing so previously saved a snapshot while omitting its
resource/index projection. Bulk and live paths now use one transactional write
and propagate failures. No automatic choice of winner, deletion or relinking is
performed. The new regression uses independent databases and the transport engine,
not two operating-system processes or a real network connection.

## Browser follow-through

Incremental sign-at-drain now includes datatype tags for newly added JSON and
reference properties. A failing JSON-roundtrip regression exposed this during
primary selection. The review UI confirms the decision through a detached server
snapshot, so a queued or rejected local edit cannot produce a success message.
`findByLocalId` refreshes both membership and record contents from the server.
WASM bulk/JSON-AD replica ingestion preserves duplicate identities, matching native
replica persistence; it no longer retains a stale projection after rejecting them.
Its bootstrap currently indexes incoming resources and performs the existing final
parent-dependent index rebuild; performance of that extra work remains unmeasured.

Existing installed JS importers need their normal reviewed code update to recognize
primary decisions. No installed source or live provider data was silently replaced.

## Reviewed consolidation follow-through

- [x] Choose each differing application field from a reviewed copy, including
  choosing an absent value. Unselected fields keep the primary's value.
- [x] Native validation checks every reviewed member and the exact resulting
  projection. Core fields other than name and description remain protected;
  source baselines stay unchanged so consolidation counts as a local edit.
- [x] Unit-tested bounded reference preview for typed application links. It
  preserves array order/multiplicity and ignores text, opaque JSON, core
  hierarchy/security fields and the reviewed copies themselves.
- [x] Connect indexed incoming-reference discovery and field selection to UI.
  Signed per-record preconditions reject stale values in both author-intended and
  merged Loro state. Confirm against detached server reads; report partial failure
  per record and recover acknowledged values without resending writes.
- [x] Reopen review from the primary record page; original histories are excluded.
- [ ] Graph-wide coverage: discovery is limited to readable indexed references in
  the selected drive and refuses more than 1,000 candidate records. Core links
  (including parent), text and JSON are excluded. There is no atomic transaction
  across records or rollback of already confirmed writes.
- [x] Browser acceptance and local runtime restart for consolidation and link
  review. New Chromium coverage preserves a manually edited link during partial
  application, confirms the other record, then reopens review from the primary.

Browser testing exposed two implementation details: incoming-value indexes include
commit histories (exclude them explicitly), and schema datatypes use atomicURL,
while Loro tags use atomicUrl. Discovery now reads actual Property datatypes and
uses the standard datatype constants. Initial whole-drive discovery encountered
changing membership from generated query resources; direct incoming-value lookup
avoids scanning unrelated resources.
