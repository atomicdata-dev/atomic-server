# Silent failures

> **Status:** Living log, not a plan. An append-only register of error-handling failures that reported success. It has no completion state; add entries as they are found.

A running list of places where **error handling** let us down — kept separately
from the bugs themselves.

The pattern is always the same: a command reports success, a health check
passes, a tool "updates" nothing, and the damage surfaces hours later disguised
as an unrelated bug. Almost every expensive debugging session here has been a
silent failure rather than a hard one. The time goes into *discovering that
something did nothing*, not into fixing it.

**Rule of thumb:** prefer failures that cannot be missed — refuse to start, wipe
the bad state, exit non-zero — over printing a note. Notes scroll past, and most
of these tools run with output redirected to a log nobody reads.

Each entry: what happened, what it looked like, what should have shouted.

---

## Build and deploy

**`ATOMICSERVER_SKIP_JS_BUILD=true` silently embeds a stale frontend.**
The flag reuses whatever bundle was embedded last. `cargo build` prints success.
The server then serves a frontend older than its own sources — and since the
data layer is TypeScript, a fix that lives in the browser package is simply
absent while everything looks freshly deployed.
*Should have:* warned, at minimum, that the embedded bundle is older than the
sources it was built from. The README recommended this flag for e2e, which is
precisely where it does the most damage.

**A typecheck artifact in `dist/` made `build.rs` skip the JS build.**
`tsconfig.build.json` sets `outDir: ./dist`, so a plain `pnpm typecheck` drops
`tsconfig.build.tsbuildinfo` beside the bundle. `build.rs` compares the newest
file in `dist` against the sources, so that one file read as "dist is current".
Observed: sources 14:42, tsbuildinfo 14:43, actual bundle 13:47 — and a 17s
"successful" build. Cost several wrong diagnoses, one of them confidently
blamed on unrelated work.
*Should have:* compared against a file the JS build actually produces, and said
"skipping JS build because X is newer than Y" loudly enough to notice.
*Fixed 2026-08-18 (28865b4e).*

**A stale server binary diverges from vite, invisibly.**
`build.rs` embeds the data-browser bundle, and the invite and dev-drive pages
are served from *that* copy while every other page comes from vite. A binary
built on another branch therefore serves two different frontends at once. Three
e2e specs failed in a way that looked like a bug in the personal-drive work.
*Should have:* refused to run the suite against a binary older than its sources.
*Fixed 2026-08-18 (87e12c9a) — `test-server` now refuses and names the file.*

**The embedded bundle was only refreshed when the build *itself* built it.**
`build.rs` gated the `dist` → `assets_tmp` copy on `needs_build`, which answers
"are the JS sources newer than dist" — should `pnpm build` run — not "is the
copy I embed current". Those diverge precisely when you build the frontend by
hand, which is what a deploy does. dist is then fresh, `needs_build` is false,
the copy is skipped, and the binary ships an older `assets_tmp`. The more
carefully you prepared, the more certainly you shipped a stale bundle.
Surfaced only by comparing the chunk hashes in the served `index.html` against
the local `dist`; the binary's md5 matched what was built, and the build said
nothing.
*Should have:* compared the two directories, which is the actual question.
*Fixed 2026-08-19 (5a39f546).*

**`pnpm build` printed "Build Finished!" after the declaration step failed.**
`tsup` runs `tsc --emitDeclarationOnly --declaration` and its failure did not
stop the build reporting success — so a local "lib built" check passed while CI
failed on the same command. The diagnostic (`error TS2345` in a test file) was
only visible by running `tsc` directly.
*Should have:* a build that emits nothing usable is a failed build; it should
exit non-zero and print the diagnostics where the person running it will see
them.

## Test harness

**An oversized `.e2e-store` invents 4–8 different failures per run.**
The script printed a NOTE past 150MB and carried on. The usual way to start it
is backgrounded with output to a log, so nobody read it. One full suite takes a
fresh store from 5MB to ~103MB, so the line is always about a run and a half
away.
*Should have:* wiped it. A warning is the wrong shape when the consequence is a
failure list that changes every run.
*Fixed 2026-08-18 (87e12c9a) — wipes by default, `--keep-store` to override.*

**`waitForSearchIndex(page)` with no query is a 1.5s sleep wearing a
readiness-helper's name.**
It "succeeds" whether or not the index is ready. Held on a warm store, failed on
a fresh one.
*Should have:* required the query, or at least not presented a fixed sleep under
a name that promises a readiness check.
*Fixed 2026-08-19 (a0ecf095).*

**Playwright's `-g` silently keeps only the last one.**
Passing two spec files with two `-g` filters ran one test and reported
`1 passed`. Nothing indicated the other filter had been discarded.

**No `webServer` block, so every spec fails on a dead port.**
With no dev server on 6747 the whole suite fails at `page.goto` with
`ERR_CONNECTION_REFUSED`, which reads as a suite-wide code regression.
*Should have:* one clear "nothing is serving 6747" rather than 176 identical
connection errors.

## Sync and data

**Hydration writes entered the outbox as if they were user edits.**
Opening a resource you can read but not write queued a commit the server rejects
forever. Those went through the entire backoff ladder and parked as blocked
entries, visible only in an activity feed. Underneath, `isOwnedSubject` answered
a *rights* question with a *domain* answer and no one noticed because it never
errored.
*Should have:* not been possible to enqueue a write nobody asked for; failing
that, a rejected write should surface where the person who caused it is looking.
*Fixed 2026-08-18 (ecaa4a63).*

**A client renders a stale row set and never reconciles with its server.** *(open)*
The Houseplants table showed 22+ rows on desktop and 15 in the browser against
Home Assistant. It looked exactly like a sync failure, and the peer log
supported that reading: `SYNC_DIFF: server pushes 0, server pulls 1` — "I have
nothing to send you".

It was not a sync failure. Running the same collection query against both
servers returns **24 members from each**: identical resource sets, identical
query index. The servers were converged the whole time and `pushes 0` was
correct. One client was simply displaying a stale local index, and nothing —
not the client, not the server, not the sync page — indicated that what was on
screen disagreed with what the server held.
*Should have:* a client that answers a collection from its local index while
the server holds a different count is the single most misleading state in the
system, because it is indistinguishable from a sync bug and sends you into the
sync code. It needs to be visible: reconcile against the server and say so, or
surface the disagreement.

*Diagnostic note, and a lesson in its own right:* three separate signals pointed
at the servers disagreeing — different row counts, a `pushes 0` diff, and rows
with `lastCommit` the peer "did not have". All three were consistent with the
wrong conclusion. What settled it was querying both servers directly and getting
24 = 24. Measure the thing itself before believing a story that explains the
symptoms.

**`fetchResourceHTTP(url, {agent})` silently ignores the option.**
Returns `Unauthorized` rather than either signing the request or rejecting an
unknown option. Reads as a permissions problem, is actually a typo-shaped API
gap.

**A query index silently disagreed with the data it indexes.** *(open)*
The Houseplants table rendered 5 rows on the desktop node and 22 on Home
Assistant. Every resource was present on both, and every probe said they were
converged — because the probes were reconstructions of the table's query rather
than the query itself.

The table asks for children of the table, filtered by classtype, sorted by the
view's sort property, scoped to the drive. That combination routes through
`query_complex`, whose index is keyed by drive. On the desktop node it returns
**5**; drop the drive scope OR the sort and the same server returns **22**. Home
Assistant returns 22 for all three shapes. So one index held 5 of 22 rows while
the resources, the unscoped index, and every other query shape were complete.

*Should have:* an index that cannot answer for rows it is supposed to cover is
the definition of a silent failure — the rows are simply absent, with no error,
no warning, and nothing to distinguish it from "there are only 5 rows". It needs
a consistency check between an index and the resources it claims to index.

*Diagnostic lesson, which cost most of the day:* every measurement I took was a
query I composed — `parent=<table>` — and it returned 24/24 from both servers,
over and over, while the UI showed 5 and 22. The reconstruction differed from
the real query in exactly the parameters that break. Capture what the
application actually sends (patch the fetch, read the server's access log)
before comparing anything. "Both servers agree" is worthless if the question is
not the one the product asks.

## Environment and deployment

**A Home Assistant add-on pinned to an image tag nobody publishes.**
`latest` came from a one-off manual push in June 2026; CI only refreshes
`develop`. "Update" re-pulled the same digest and reported success, so the
add-on served a two-month-old server while looking current.
*Should have:* a publish pipeline that never leaves a referenced tag stale, and
an add-on that surfaces the image digest/age it is actually running.
*Fixed 2026-08-19 — add-on now tracks a tag CI publishes.*

**A Cloudflare tunnel pointing at a stopped add-on.**
`atomic.ontola.io` returned 502 while Atomic was healthy and serving. The
ingress named a container that no longer existed; only cloudflared's own log had
`no such host`, and the add-on itself reported `started`.
*Should have:* the tunnel's ingress targets are configuration that can be
validated — an unresolvable origin should be visible where the add-on's health
is shown, not only in a log.

**`ha addons reload` reports success without reloading the add-on repo.**
The config change had merged upstream and HA still showed the old version.
`ha store reload` is the one that works.
*Should have:* not returned "Command completed successfully" for a no-op.

**Two add-ons for the same app have separate databases.**
Repointing the tunnel between them silently switches the entire dataset. Nothing
indicates you are now looking at different data — which is exactly the kind of
thing that makes a sync investigation chase ghosts.

**vite started from the repo root serves the built `dist/index.html`.**
No config loaded, no error — the Tauri window is simply white. The only clue was
an unresolved-dependency warning about `plugin-examples/`, which looks unrelated.
*Should have:* refused to start, or said which config it loaded and which root
it is serving.

**A running vite rewrites `src/locales/*.po` during git operations.**
Two writers (dev server + a build, or two dev servers) corrupt the catalogs.
Shows up much later as `[i18n-404]` or a misleading "Invalid hook call".
*Should have:* a lock, or a refusal to extract while another extractor holds the
catalogs.

**An AI chat is unsaved for the whole time the model is generating.**
A sidebar chat stays an in-memory draft until the first assistant reply
*completes*, so a reload mid-turn loses the prompt, the partial reply and the
chat resource — and the chat never appears in the AI Chats panel, because no
resource was ever created. Nothing logs and nothing toasts: no error path is
reached, because there was no failed write, only an absent one.
*Should have:* said that a conversation was discarded. An absent write is not an
event today, which is exactly why this went unnoticed until a long
code-generation turn made the window wide enough to hit.
See [`ai-chat-draft-persistence.md`](./ai-chat-draft-persistence.md).

## Carried over from the pairing field test (2026-09-04)

The field notes moved to [`completed/pairing-ux-field-test.md`](./completed/pairing-ux-field-test.md); the item below is the one still open that belongs here.

### M8 — "Your changes are saved locally" is false on desktop (open)

Offline edits mark subjects dirty in the outbox, but the *content* lives in the
Loro doc, which is persisted by the ClientDb: "On reload the Loro doc rehydrates
from clientDb" (`local-outbox.ts`). The desktop app runs with the ClientDb off
by design — the embedded server is meant to be the local store — so while
offline, edits exist only in memory and a restart loses them, under a toast
promising the opposite.

Server-side durability is not the problem: `serve.rs` runs a 100ms durable-flush
tick, and the desktop goes through that same path.

Either the outbox must persist content without the ClientDb on this platform, or
the app must not claim local safety it does not have.
