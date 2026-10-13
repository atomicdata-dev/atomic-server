# Completion and recovery contracts

Rendering an edit, storing it on this device, receiving a server acknowledgement,
and including it in a backup are separate events. APIs should report the event
they established so callers can choose the guarantee their operation needs.

## Saving from TypeScript

`Resource.save()` retains its compact result:

| Result | Meaning |
| --- | --- |
| `persisted` | Accepted by a server, or durably written on a local-only drive |
| `offline` | Written locally with retry state for a server |
| `queued` | Waiting for an unsaved parent; no durability guarantee |
| `noop` | This call had nothing to save; it establishes no new guarantee |

Use `Resource.saveWithReceipt()` when that distinction matters:

```typescript
const receipt = await resource.saveWithReceipt();

if (receipt.server) {
  // This endpoint accepted this commit and encoded Loro version.
  const { endpoint, commit, version } = receipt.server;
}

if (receipt.local) {
  // The local database completed its durable write barrier.
  const { version } = receipt.local;
}
```

The receipt names the resource after any genesis rename. Versions are base64
encoded Loro version vectors; a local unversioned metadata row uses `null`.
Each version belongs to its completed boundary. An edit made while a request
was in flight is not covered by that request's older acknowledgement. The local
mirror can contain a newer revision than the server receipt.

A server acknowledgement can succeed while the optional local mirror fails.
In that case the save succeeds and has no local receipt. A local-only or offline
save must reject when its required storage is missing, unsupported or fails to
flush. The edit and retry information remain available. Peer transmission is
independent and does not establish backup coverage.

A server receipt reports acceptance, not the server's physical storage policy.
It also does not prove that another device has received the edit, that referenced
file bytes were uploaded, or that a Vault checkpoint contains it.

## Applying incoming state

`Store.applyIncoming()` accepts exactly one representation: a Resource or Loro
bytes. Ambiguous and missing payloads are rejected. Its synchronous `applied`
result means that the in-memory view changed; the asynchronous database mirror
has a separate completion boundary.

Incoming snapshots merge with existing causal history. A stale HTTP or WebSocket
response cannot discard a newer peer update simply because it is a snapshot or
a forced refresh. Only a projection rebuilt from JSON, with no pending local
edits, can be replaced by causal state. An incompatible import fails instead of
resetting local history to the incoming resource.

Computed query answers are an exception: each response replaces the previous
projection so its member list and count stay consistent. Query answers have no
shared edit history; the editable resources nested inside them still merge.

Offline queue recovery merges the stored snapshot with the live document before
exporting unsent changes. A cached snapshot cannot replace newer in-memory edits.
Legacy queues recover their baseline from the signed genesis; normal online
saves do not depend on the local database becoming ready.

## Recovery and identity

Recovery distinguishes complete, partial, absent, unavailable, and cancelled
outcomes. A configured backup service that cannot be queried has not established
that a backup is absent. Missing local storage or device identity is also an
unavailable dependency. Partial recovery keeps readable data and remains visible
as partial.

Absence used to create a default home is scoped to the queried drive, agent and
identity generation. A mere "recovery attempted" flag cannot authorize creation.
Standalone installs explicitly report that no managed backup service is
configured; they retain independent local/server operation.

`Store.getIdentityGeneration()` changes when its Agent object changes, including
sign-out followed by sign-in as the same agent. It is local to that Store, is not
persisted or a key epoch, and can fence delayed work. Recovery also checks the
selected database and managed session before publishing results.

Managed invitation handoffs carry both the signed token and its node origin
through email and identity recovery. The resumed destination is always the
app's invitation screen. It extracts the token and server from the invitation;
an arbitrary redirect field is never followed. Legacy token-only links remain
readable, but do not themselves identify a node.

## Further guarantees

These contracts do not yet provide per-drive routing ownership, proof of all
backup dependencies, Vault-only blob upload, or complete query/notification
coverage. See the repository's `TESTING_COVERAGE.md` and active
`planning/sync-contracts.md` for those remaining boundaries.
