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

Server reads also check placement before applying data. A response cannot claim
a resource or drive already assigned to another origin, including through nested
HTTP resources or batched WebSocket reads. An unsolicited update for an unknown
drive uses the configured bootstrap destination; an unrelated open connection
cannot claim it. An explicitly requested vanity URL may establish a previously
unknown drive's origin. This trusts the chosen server; it does not authenticate
an arbitrary server's claim to host a previously unknown drive.

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
an arbitrary redirect field is never followed. Invitation URLs cannot select the
startup signing server. The screen requires confirmation of an unrecognized exact
origin before mounting invite readers or changing servers; sibling subdomains are
separate origins. Legacy token-only links remain readable but do not name a node.

## Subscription and query ownership

A `Store.subscribeLive()` holder releases its interest at most once. Switching
accounts invalidates old holders, so their later cleanup cannot unsubscribe a
new account. `getRoutingGeneration()` fences delayed routing decisions, including
a switch away and back to the same route. Anonymous public subscriptions remain
held through first sign-in; switching existing accounts revokes their old holders.

Each drive has an account-scoped server origin. `setDriveServer(drive, origin)`
sets or explicitly migrates that placement. Changing the default server alone
never migrates an existing drive. Reads, commits, queued work, queries, blobs,
subscriptions and reconciliation use the owning drive. Exact scheme, hostname,
subdomain and port matter. Connection and reconciliation state are per origin and
drive, so one offline destination cannot pause another drive's writes.

A cold opaque resource ID needs its drive hint, a scoped query that discovered
it, or a previously recorded route. HTTP root aliases preserve the resource's
canonical identity and record the resolved origin. Identity/placement changes
cancel late reads and receipts. Queued mutations persist their destination with
the local snapshot. Parentless Agent profiles are shared identities: a fresh
profile edit publishes to the selected node, while an already queued edit retains
its destination. This does not claim profile fan-out to every previous node.

`Collection.completeness` is `complete`, `partial`, or `unavailable`. A complete
query was answered by its authority or by a reconciled/local-only index for its
scope. It does not assert that offline peers have no newer edits. Call
`getAllMembers({ requireComplete: true })` for operations that need all members;
an unavailable index must not authorize a claim that the result is empty.
Account, database or routing changes invalidate previous completeness evidence.

## Vault metadata coverage

WASM and desktop serialize the core `RestoreSummary`, including `completeness`,
`objectsMissing` and `objectsUnreadable`. A later segment or a checkpoint's
observed heads can prove an earlier segment is missing. Only checkpoint coverage
can excuse that gap. Imported lane coverage advances through contiguous recovered
segments, so a partial restore cannot authorize pruning the missing history.
Old import cursors that did not establish this guarantee are discarded on upgrade;
resource and backup cursors remain intact. Readable auxiliary index/blob envelopes
are skipped by graph import; a required pack/checkpoint key with the wrong kind
is still unreadable. Callers must stage the complete object inventory before one
import call. Download URL batching is not an import boundary. Legacy history with
unprovable earlier segments remains unprunable until a covering checkpoint or
complete prefix establishes safety.

Format 3 packs authenticate their attachment dependencies. Encrypted attachment
chunks live in separate blob objects and are uploaded before graph backup is
confirmed. Recovery verifies their hashes before reporting complete. Graph
recovery can retain readable resources while reporting missing or corrupt files.

Recovery compares the downloaded inventory with independently retained confirmed
lane/checkpoint heads. This detects an omitted tail that the listing alone cannot
prove missing. The key and its authenticated epoch travel together through the
browser, worker and native adapters. A rollback that removes every independent
recovery witness remains outside this guarantee; legacy backups cannot recover
attachment bytes that were never uploaded.

Browser notification catch-up and read/unread receipts converge after reconnection,
including after the receiving browser reopens. Push while every app remains closed
and packaged native notification activation are separate gaps. See
`TESTING_COVERAGE.md` for the executed cases and remaining limits.
