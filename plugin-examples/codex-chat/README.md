# Codex chat for Atomic

A source-as-data app for AtomicServer's `feat/plugin-model` branch. Open a
conversation, send a prompt, watch replies, inspect command/file activity, stop
work, and answer command/file approval requests. Conversations and turns are
ordinary Atomic resources; Codex retains its execution/session state locally.

This is an **Atomic plugin for Codex**, not a plugin installed into the Codex
marketplace. It uses `createApp`, an exported `view({ root, store })`, scoped
Atomic agents, and the existing v1 view protocol. The browser catalog installs it; the view uses the existing iframe RPC operations.
The worker needs no public listener or shell execution inside the view.

## Run

Requires this repository at `feat/plugin-model` (tested base `f09b0a4af`), Node
22+, pnpm, a running AtomicServer with that plugin API, and an installed/authenticated
Codex CLI. The worker starts its own `codex app-server --stdio` process.

From the repository root:

```sh
pnpm --dir browser install --frozen-lockfile
pnpm --dir plugin-examples/codex-chat install
node plugin-examples/codex-chat/build.mjs
```

### Connect from Atomic

1. Open **Integrations → Codex → Set up connection → Create Codex app**.
   Click **Download worker setup** before closing the dialog.
2. Open a terminal in the **AtomicServer checkout where you ran the build above**.
   Configure the worker once:

   ```sh
   node plugin-examples/codex-chat/dist/cli.js connect ~/Downloads/codex-setup.json ./codex-connection.json "$(pwd)"
   ```

   The final argument is the **project folder Codex will work in**. `"$(pwd)"`
   uses your current AtomicServer checkout. For a different project, replace it
   with the full folder path in quotes, such as `"/Users/you/projects/my-app"`.
   You can run `pwd` in any project's terminal to find that folder's full path.
   Adjust `~/Downloads/codex-setup.json` if you saved the download elsewhere.
   `./codex-connection.json` is the new local configuration file, not the project
   folder; keep it and its companion files for future starts.
3. After **Worker configured**, start the worker from the **same directory**:

   ```sh
   node plugin-examples/codex-chat/dist/cli.js work ./codex-connection.json
   ```

   Configuration alone does not start the worker. Wait for **Codex worker ready**,
   and keep this terminal running.
4. Click **Open Codex** in Atomic (or select it in the drive sidebar), then send
   a message. Press **Ctrl+C** in the terminal to stop the worker. To restart it
   later, return to this checkout and run the same `work` command; do not rerun
   `connect`. Messages submitted while the worker is stopped remain queued.

The downloaded setup contains the app-scoped secret: keep it private. The
catalog entry is part of this branch, not a released integration.

Alternatively, install from the CLI. Set `ATOMIC_SERVER_URL`, `ATOMIC_DRIVE` and `ATOMIC_AGENT_SECRET` in your local
environment. The latter is an Atomic agent secret with permission to create an
app in the chosen drive. Keep it out of shell history and shared files.

```sh
node plugin-examples/codex-chat/dist/cli.js install /absolute/private/connection.json /absolute/workspace
node plugin-examples/codex-chat/dist/cli.js work /absolute/private/connection.json
```

Open the new **Codex** app in your drive's sidebar. The installer prints its
subject. Set `CODEX_BIN` if the CLI is not on PATH. The Codex model is inherited
from your CLI settings. This client explicitly starts threads in **read-only**
sandbox mode with on-request approvals routed to the user. It never auto-accepts
approvals. Unsupported interactive request types receive an explicit RPC error.

The installer creates the app, a Conversations table, schema, view, and a scoped
app identity. It registers that identity using the existing `/app-agent` API.
Its credential is written to `connection.json.secret` with mode 0600, separately
from the public connection file. The worker reads only that app's resources;
its fixed filesystem workspace comes from the local connection file, never a
remote resource. Anyone granted write access to this app can enqueue prompts
and answer approvals for this worker: share it accordingly.

The view module is stored inside Atomic, so data remains browseable if the
worker is offline. Changes to `view.js` require updating the installed app's
entrypoint source (keep its injected CONFIG bindings). Reinstalling creates a
separate app. Failed installation can leave a partial app and reserved config
file; inspect those before installing to a new filename.

## Recovery and current scope

Run exactly one worker per app, using the same connection file. A local `.lock`
prevents simultaneous workers using that file. After a hard crash, check the
recorded PID is no longer running before removing the stale lock. Multi-host
worker election is not implemented.

The local `.journal` durably records claimed prompts and conversation/thread
bindings before execution. Keep it with the connection file. A restarted worker
marks interrupted/claimed requests **uncertain** and never replays them. It
blocks that conversation until an operator checks the associated Codex task.
After checking the outcome, use Atomic's data view to change the uncertain
turn's state to `interrupted` before sending a fresh prompt. Do not erase the
journal to retry a prompt. A network timeout is not proof execution failed.

Included: text conversations, streamed agent text and command output, saved
turn items, continuation, Stop, approve-once/decline for command/file requests,
worker heartbeat and visible errors. Turn state and replies flush every polling
cycle, not every token. Queued prompts wait while the worker is offline.

Not yet included: import of existing desktop chats, attachments, full diff
review/editor, arbitrary forms or permission-grant requests, multi-worker
coordination, automatic recovery reconciliation, or a
standalone distributable package. Polling currently lists app conversations and
turns; a large archive needs indexed pending-request queries/pagination in the
view. Atomic storage does not make model inference local.

## Verification

```sh
node plugin-examples/codex-chat/test.mjs
pnpm --dir plugin-examples/codex-chat typecheck
pnpm --dir plugin-examples/codex-chat exec playwright install chromium
node plugin-examples/codex-chat/view.test.mjs
```

The eight protocol/worker tests cover interleaved streaming, completion,
restricted approval choices, RPC errors/process exit, actual worker approval
round trips, cancellation and no-replay recovery. The browser fixture test
covers sending, queued/reply rendering, switching conversations, approval,
Stop, HTML escaping and mobile layout; screenshots go to `dist/`.

For two explicitly authorized live no-tools model calls while the worker runs:

```sh
ATOMIC_CODEX_LIVE=1 node plugin-examples/codex-chat/dist/live.js /absolute/private/connection.json
```

This creates a labelled test conversation and checks both saved responses,
thread identity and retained context. It leaves the conversation for inspection.

Local validation on 2026-09-11: installed from the full Data Browser's
Integrations catalog into an isolated AtomicServer, downloaded the worker setup,
and opened the hosted chat in Atomic's sidebar. A UI-submitted prompt was read
back from Atomic as queued while the worker was stopped; starting the worker
produced a real Codex response persisted in Atomic.

The iframe regression runs with native forms disabled, matching Atomic's
sandbox. The host refreshes reads so external worker writes do not remain
stale in the browser cache. The test server used the existing local AtomicServer
development binary; the Rust workspace was not rebuilt. Live command/file
escalation has not been certified.
