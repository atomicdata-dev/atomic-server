# Shared integration actions

Connections declare named actions alongside allowed operations. UI, Atomic
assistant, JavaScript automations and the MCP stdio host use the same signed API.
The host validates the actor, pinned release, configuration and arguments, then
runs the request builder in QuickJS/WASM without capabilities. Provider
credentials stay in the host.

Inputs support a deliberately bounded JSON Schema subset: object,
string/integer/boolean fields, required fields and `additionalProperties: false`.
Unsupported keywords are rejected. GitHub provides `get_issue` and `create_issue`;
Notion currently provides sync rather than named actions.

## Direct calls and review

Reads execute immediately. Direct writes from the UI, assistant or MCP save an
immutable proposal. Review shows its destination and inputs, with the exact
request available in a disclosure. Approval requires the original actor and
unchanged connection; proposals expire after 15 minutes. Pending actions can be
cancelled. Cancellation retains their identity so a retry cannot recreate them.

Use a stable ID per logical call. Completed writes return `completed` with the
saved receipt; uncertain or failed writes are never automatically sent again.
The actor/connection limit is 60 fresh calls per minute and 100 active proposals.
Retries of saved calls do not consume the fresh-call allowance.

## Automation permissions

Connections have an **Automation action permissions** disclosure. Select a
referencing automation, one action and either **Review each write** or **Allow
automatic writes**. Permissions expire after 30 days and can be revoked there.
They pin the granting actor, connection release/configuration and the actual
executing JavaScript hash. Edits cannot inherit permission. The caller and
connection must both remain writable by that actor and explicitly linked.
App-scoped plugins additionally require this dedicated grant, including reads.
Manual previews still require review even with an automatic-action grant. Only
event and cron execution uses automatic grants. Sync schedules and their approvals
are independent.

```js
const result = ctx.integration({
  connection: "did:ad:...", // included in automation-integrations
  release: "...", // exact release from listIntegrationActions
  call: {
    action: "create_issue",
    arguments: { title: "A new request" },
    id: `${ctx.trigger.id}:create-issue`,
  },
});
// After approval, result.status is "completed" and result.result is the receipt.
```

The host records an integration wait when a write needs review, even if the
script ignores the returned value. It does not apply the rest of that run's
Atomic intents. Event and cron workers persist the wait and resume the same
input after approval or confirmed recovery. Replay reruns the JavaScript and
reuses write receipts; it is not a snapshot of arbitrary reads. Code/account
changes refuse continuation. Use stable step IDs and handle provider results as
untrusted data. Changed arguments for an existing write ID are refused.

## History and recovery

**Action history** keeps completed, failed, uncertain, cancelled, expired and
stale actions visible, with provider receipts and recovery evidence. It shows
50 entries at a time, with **Load more actions** for older records. For an uncertain write, **Check and recover** asks for a
declared read action and identifying inputs, plus evidence explaining the match.
The host performs that read and saves its result. The user reviews it and confirms
that it is the original write's result. Confirmation expires after five minutes,
checks the actor/configuration again and never resends the write. This is an
operator assertion, not an automatic proof that the lookup matched the write.

**Clean up old action details** previews up to 100 records, then offers an explicit
archive action. Unsent manual proposals older than 30 days are eligible. The UI
also includes successful manual actions whose receipt was settled at least 30 days
ago. Settlement time is recorded when a provider response is persisted or recovery
is confirmed; proposal creation time alone is insufficient. Legacy receipts with
no settlement timestamp, failed and uncertain writes, and automation-originated
records without complete, finished consumer tracking remain protected. Cleanup does not run automatically.

Archived proposals retain their ID, actor, action, title, release, timestamp,
outcome and a hash of the original proposal. Inputs, configuration, destination,
headers and request body are stripped. Completed journal entries retain their key,
response status, settlement time, recovery evidence and a payload hash; request
and response bodies are cleared. Any duplicate saved recovery lookup is removed
in the same transaction. Reusing the named call or the external executor identity
fails explicitly: neither can return a misleading empty success or send again.

POST `/integration-action-history-compact` accepts a signed `{drive, plugin,
cursor?, apply?, includeCompleted?, includeAutomation?}` request. Omitting `apply` previews only;
omitting `includeCompleted` preserves the older unsent-only policy. The UI opts in
to completed manual actions after explaining that scope. The response includes
`scanned`, `eligible`, `compacted`, `reclaimableBytes` and `nextCursor`. Each batch
rechecks ownership, age and eligibility under the action/external locks, then
atomically writes proposal and journal tombstones. Counts refer to actions, not
individual database operations. Start without a cursor to seek directly to old
records; pass the returned cursor to inspect the next batch. Byte counts concern
serialized payloads; redb may reuse space without shrinking its file.

Cleanup is not exposed as an assistant or MCP tool. Automation cleanup is an
additional opt-in (`includeAutomation`, default false), enabled by the current UI.
For automation actions, the host records every consuming run before returning a
receipt. Cleanup requires complete ownership tracking and a durable completion
successful-completion or explicit-abandonment marker at least 30 days old for **every** consumer; successful provider receipts
must separately meet the settlement-age check. The existing connection lock
serializes consumer registration and compaction. A new unfinished consumer blocks
cleanup; if cleanup wins first, the archived ID refuses subsequent consumption.

The host captures the run identity before JavaScript starts. Only the internal
cron/query execution path can attach ownership or use automatic action grants;
ordinary/public runs cannot impersonate it through `input.trigger`. Completed run
identities cannot consume receipts again. A receipt can have up to 1,000 consuming
runs; use per-event call IDs for new work rather than sharing one indefinitely.
Legacy actions without complete tracking, and actions subsequently accessed from
an untracked/manual run, remain protected. Tracking is never inferred retroactively.

Runs have a durable completion marker after effects and run-log persistence;
workers use it to acknowledge a completed run without rerunning JavaScript after
a crash. Crashes before that marker retain their receipt protection. Interrupted
runs retain their protection until they complete or an authorized operator
explicitly abandons them. Production load validation and automatic retention
scheduling remain open.

### Abandoning a consuming run

In Action history, **Automation runs using this action** lists recorded consumers.
Inspect the run, provide a reason and choose **Abandon this run**. This permanently
stops that run; it does not undo existing effects or disable future scheduled runs.
Abandonment is stored separately from successful completion, with the operator,
reason and timestamp. Repeating the request preserves the original audit record.

The signed `/integration-action-consumers` endpoint takes `{drive, plugin, id}`.
`/integration-action-consumer-abandon` additionally takes `run` and `reason`.
The actor must own the action and have write access to both the connection and
its automation; the run must be one of the action's recorded consumers. A busy
worker refuses abandonment. A deleted/inaccessible automation must be restored or
have access reconciled first; this endpoint does not bypass its authorization.

Workers acknowledge abandoned runs without executing them. Further planning,
receipt consumption or successful-completion marking is refused. If every tracked
consumer of a pending action was abandoned, approval cannot start a new provider
write. Shared actions with another consumer stay usable. Uncertain provider
outcomes are never relabeled successful. Retention waits another 30 days from
abandonment and still applies all receipt-age and uncertainty guards. Neither
inspection nor abandonment is exposed through the assistant/MCP action adapter.

History uses an actor-scoped descending timestamp/ID index. POST
`/integration-action-history` with `limit` (1–100) and optional `cursor` returns
`{entries, nextCursor}`. Omitting both preserves the old latest-100 array response.
Cursors only seek inside the authenticated actor's connection history. Equal
creation times have an ID tie-breaker, so newer inserts do not shift older pages.
Existing records are indexed once in restart-safe batches; new proposals and
index entries are written atomically. redb applies page limits before copying
values. Pending approval checks only scan the last 15 minutes.

The local regression seeds 2,001 records and exercises migration, tied timestamps,
concurrent insertion, actor isolation and invalid cursors/limits. This is a local
scaling regression, not a production throughput or retention certification.

## MCP stdio host

After installing the browser workspace dependencies and building `@tomic/lib`,
run `node browser/data-browser/scripts/integration-mcp.mjs`. Configure an MCP
client with that command and these environment variables:

- `ATOMIC_SERVER_URL`: AtomicServer HTTPS origin (loopback HTTP is allowed for tests).
- `ATOMIC_DRIVE`: drive subject.
- `ATOMIC_CONNECTION`: one installed connection subject.
- `ATOMIC_AGENT_SECRET_FILE`: local file containing an Atomic agent secret with
  access to that connection. Restrict the file to the current OS user.

The existing MCP SDK handles initialization and stdio transport. The adapter
signs requests as that agent and exposes only the connection's actions; no
approval, grant or recovery-confirmation tools are exposed. Configure
`_meta: {"atomic/callId": "stable-id"}` for retry stability. No additional
listening service or provider credential store is required. Remote HTTP/OAuth
MCP deployment is a separate hosting choice, not part of this stdio host.

Tests cover real stdio initialization and signed calls against a loopback fixture,
sandboxed action preparation, actor/code/configuration grant checks, revocation,
recovery, event/cron continuation and browser review controls. Live provider
failure recovery and production load are not certified by those tests.
