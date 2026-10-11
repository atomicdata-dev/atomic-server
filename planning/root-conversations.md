# Root conversations: a Conversation is a root resource, not a Drive

> **Status:** Design (2026-10-11), nothing built. Joep approved the direction:
> a conversation is a root-level `Conversation` resource with `read` and
> `append` for its members and `write` for nobody, its messages are `ChatLog`
> pages that are its children, and it is stored separately and not counted as
> a drive. Builds on [`encrypted-conversations.md`](./encrypted-conversations.md)
> and [`chat-log.md`](./chat-log.md). Grounded in `origin/develop` at `77a2e85`.
> Every code claim below was read in that tree; things I inferred and did not
> run are marked **(inferred)**.

## Why

A conversation is a drive today, so everything that counts, admits, bills or
lists drives counts it. One DM is one drive; a node with an allowlist admits a
drive only when it is enrolled, and gives an unenrolled one a ten-minute grace
(`lib/src/sync/policy.rs:149`, `DEFAULT_GRACE`) before every write is refused
as "not enrolled". So on a managed node a DM either spends a drive slot or
stops working. A conversation needs the opposite: cheap, created by whoever
starts it, admitted because a *member* is hosted, never a workspace.

## Reality check against the brief

Two things differ from what the brief assumed. Both change the plan.

1. **DMs are not ChatLog entries on `develop` yet.** `sendSealedMessage` still
   creates one `SealedMessage` resource per message, as a child of the
   conversation (`browser/data-browser/src/helpers/conversations/conversations.ts:160-192`),
   `useChatLogPages` is disabled for conversations (`hooks/useChatLog.ts:29`),
   and `planning/chat-log.md` lists DMs as build-order step 4, not built, with
   `TESTING_COVERAGE.md` saying "DMs (later step)". This plan therefore works
   with `SealedMessage` children first and treats "DMs as ChatLog entries"
   (carrying the sealed payload in a field `s`) as its own step. If that work
   lands first on another branch, step 6 below simply disappears.
2. **Migration does not need to move anything** (see "Migration"). A
   conversation drive is already a parentless DID resource with `read`,
   `append` and the keyring on it. The only thing that makes it a drive is the
   `Drive` class in `isA`. Dropping that class in place keeps the subject, the
   keyring, the epochs, every ciphertext and every message. Re-publishing as a
   new resource would be both more work and worse: a sealed message's
   associated data is its header plus the *conversation subject*
   (`lib/src/conversation.rs:352-356`, `sealed_aad`), so ciphertext cannot move
   to a new subject without re-sealing by the member who wrote it.

## Current behavior and the code paths that make it a drive

### Creation

- Client: `startConversation` makes the resource with
  `isA: [Conversation, Drive]`, `noParent: true`, `read` and `append` set to
  the members, the keyring in `conversationKeys`
  (`helpers/conversations/conversations.ts:129-144`), saves it, removes `write`
  and saves again (`:151-155`). A note to yourself registers it as local-only
  before the first save (`:149`).
- Server: any parentless DID resource may be created by anyone
  (`lib/src/hierarchy.rs:241`, "DID without a parent can be created"), so
  creation needs no drive class.
- The server gives the signer of every new DID resource `write`, except Agents
  and ChatLog pages (`lib/src/commit.rs:1169-1196`). That is why the creator
  has to drop `write` in a second commit. **Nothing on the server enforces the
  drop (inferred from `check_rights_impl`, `hierarchy.rs:445+`: it walks
  `write` on the resource and its parents, and a creator who keeps `write`
  inherits it over every message and page below).** A modified client can keep
  `write` and rewrite the history of a conversation it created. The root model
  makes this a server invariant instead of a client convention.

### What is keyed on the `Drive` class, and what on "the root subject"

Almost everything that matters for admission and sync is keyed on the *root
subject* (`drive` stamp, or the resource's own subject), not on the class. That
is what makes this change small. The class-keyed places are the work.

| Place | Keyed on | Effect for a root `Conversation` |
| --- | --- | --- |
| `Resource::get_drive()` `lib/src/resources.rs:845-868` | class `Drive` | Returns `None` for the conversation itself. Used by commit fan-out (`server/src/commit_monitor.rs:668`), `external_change` (`:431`), removal (`lib/src/db.rs:4347`), search scoping, and the watched-query drive filter (`db.rs:3610`, `3639`). Pages are unaffected: they carry a `drive` stamp. Fix: count `Conversation` as its own scope. |
| `SUB` handler `commit_monitor.rs:283-312` | class `Drive` | A non-drive `SUB` registers only `subscriptions[subject]`, no `drive_subscriptions`. Fine, see "Live updates". |
| `Db::drive_subjects()` `lib/src/db.rs:1722` | class `Drive` (full scan) | Used to enroll existing drives when a node switches to owner mode (`server/src/host_mode.rs:403`) and in the commit/sync policy tests. A conversation is not listed, which is the point, but the owner-mode switch must also keep serving the conversations already on disk. |
| Admission gate `lib/src/commit.rs:1278-1337` | root subject: `drive` stamp, else own subject (`:1296-1300`) | A root conversation is already judged by `admit_decision(conversation)` today, like a drive. A page is judged by its stamp, which is the conversation (`commit.rs:1250-1276` stamps `drive` = parent's `drive` or the parent itself). |
| `import_sync_push` `lib/src/sync/engine.rs:1801-1860`, `admit_unknown_drive` `:1762`, live-link `peer.rs:903` | root subject | Same: subject-keyed. |
| Blobs `server/src/handlers/blob.rs:39-44` | referencing resource's drive stamp | An attachment in a conversation is judged by the conversation. |
| `collect_drive_subjects` `engine.rs:991` | root subject (BFS over the `parent` index) | Works for any DID root. No class check. |
| `per_drive_usage` `db.rs:1784` | list of subjects | Works for any root subject. |
| Query index `lib/src/db/query_index.rs:520-560`, `db.rs:3639-3643` | DID atoms consult every drive's filters; the `drive` stamp keeps them apart | A page's stamp is the conversation; `filter_drive_root` of a non-Drive root is `None` and `filter_accepts_resource_drive` then accepts (`_ => true`). Works, but loses the isolation check. Fixed by the `get_drive()` change. |
| Client `collectionBuilder.ts:169`, `views/ChatRoom/ChatRoomView.tsx:1224`, `Store.presenceScope` `browser/lib/src/store.ts:6877` | class `Drive` | `useChatMessages` scopes its queries to `thread.get(DRIVE_PROP) ?? (isDrive ? subject : undefined)`. A root conversation has neither, so queries fall back to the *active* drive and answer zero. Must treat `Conversation` as a root. |
| Client `Store.driveOf` `store.ts:1130`, `registerLocalOnlyDrive` `:1152`, `isLocalOnlySubject` `:1481` | root of the `parent` chain, subject-keyed | Class-agnostic. Pages of a local-only root are local-only via their `drive` stamp. |
| `healRefusedDrive` `helpers/managed/refusedDrive.ts:39-44` | class `Conversation` | Already special-cases conversations (only a note to yourself may move to browser-only). Stays. |
| Refusal matcher `browser/lib/src/local-outbox.ts:267` | the text "is not enrolled for sync on this node" | A conversation-specific refusal must still match, or the matcher must learn the new text. |

### Listing

- Creator: the conversation subject is pushed onto the private drive's
  `conversations` list, not `drives` (`useConversations.ts:174-181`).
- Everyone else: `GET /conversations` (`server/src/plugins/conversations.rs`)
  queries the reference index for `read == requester` with no limit
  (`Query { property: READ, value: agent, ..Query::new() }`, `:71-77`, and
  `Query::new()` has `limit: None`, `lib/src/storelike.rs:821`), then filters
  by class in memory (`:84-93`). The Messages panel refreshes it every 60 s
  and on focus (`useConversations.ts:68`, `:81-99`).

## Target model

### The class

`Conversation` (`lib/defaults/conversations.json`), no longer also a `Drive`.

- `isA` is `[Conversation]` only.
- `requires`: `conversationKeys` (already), plus `read` and `append`.
- `parent` is **unset**, always. A parent would make the conversation inherit
  that parent's `read`/`write` through `check_rights` (`hierarchy.rs`, parent
  walk), which is the opposite of the purpose. The server rejects a genesis
  that names a `parent`.
- `drive` stamp: none (a top-level resource is its own scope,
  `commit.rs:365`).
- Rights: `read` and `append` list the members (`append` a subset of `read`).
  **Nobody holds `write`.** The server enforces it at genesis: a `Conversation`
  genesis that carries `write` is refused, and the creator gets no automatic
  `write` (an exemption next to the ChatLog one at `commit.rs:1172-1173`).
  This also removes the second save in `startConversation`.
- Server-side shape checks at genesis, next to the ChatLog genesis rules at
  `commit.rs:1142-1165`: signer is in `read`, `append` is a subset of `read`,
  at most 32 members (the keyring holds one wrapper per member, so size scales
  with members), `conversationKeys` is present.
- Later commits: `check_write` on the old resource fails for everyone but
  Sudo and the node's own agent, so the keyring and members cannot change.
  That is the known limit from `encrypted-conversations.md` ("Next": epoch
  rotation), unchanged. See "Keyring and epochs" for the rule that would lift it.

### Messages and pages

- Messages are children: today `SealedMessage` resources (each sets
  `write = [author]`, `conversations.ts:180-188`), later `ChatLog` pages with
  sealed entries.
- **Who may create a ChatLog page:** any member, because page creation needs
  `append` on the chat (`commit.rs:1139` runs `check_append`, which asks
  `Right::Append` on the parent, `hierarchy.rs:216-222`; the explicit `append`
  array on the conversation grants it, `hierarchy.rs:512-541`, the
  explicit-grant loop in `check_rights_impl`). A non-member fails there. The page creator gets no
  `write` (`commit.rs:1172-1173`) and cannot set one at genesis without
  `write` on the chat (`:1142-1165`), so nobody can lock others out of a page.
- **Who may edit entries:** a signer without `write` may only add, edit and
  remove their own entries, and may not change page properties
  (`hierarchy.rs:314-`, `check_chat_log_member_commit`; applied on update at
  `commit.rs:1204-1226`). With no `write` on the conversation this applies to
  every member including the creator. No change needed.
- Reading a page: member `read` is found through the `drive` stamp shortcut
  (`hierarchy.rs` drive-first path, ~`:555`) which fetches the conversation
  and finds the member in `read`. The stamp is the conversation, so this keeps
  working for a non-Drive root.
- `get_drive()` change: `Resource::get_drive()` returns the resource's own
  subject for class `Conversation` too (`resources.rs:854-858`). One line plus
  a test. It makes fan-out, `external_change`, removal and the watched-query
  drive filter treat the conversation as its own scope. **(inferred that
  nothing relies on a root being a `Drive`; the callers listed in the table
  above only use the returned subject as a scope key.)**
- `DM entries`: `SealedMessage` stays in the ontology until the DM ChatLog step
  has shipped and migrated, then becomes legacy.

## Sync, subscription and live updates without a drive

- The client keeps what it does today: `ConversationPage` holds
  `store.subscribeLive(resource.subject)` while it is open
  (`views/Conversation/ConversationPage.tsx:52`). `subscribeLive` is
  reference-counted and sends `SUB <subject>` on every reconnect
  (`browser/lib/src/store.ts:6649-6672`, `websockets.ts:1771-1778`, `:1806-1810`).
- On the server a `SUB` on a non-drive registers `subscriptions[subject]` only
  (`commit_monitor.rs:240-315`), but a commit on a *child* also reaches the
  parent's subscribers: "Subscribers of the parent" at
  `commit_monitor.rs:681-720`, with rights re-checked per subscriber against
  the child. That path exists for a shared chatroom in someone else's drive
  and is class-agnostic. A new ChatLog page, an entry added to a page and a
  `SealedMessage` are all children of the conversation, so all reach a member
  subscribed to the conversation. **Therefore no server change is needed for
  live updates.** Pages are direct children; grandchildren (if attachments ever
  nest) would not match this path and would need the drive route.
- Why not make `SUB` treat `Conversation` like a drive (add the class at
  `commit_monitor.rs:283`)? It would also work (pages carry the conversation
  as `drive` stamp), but it skips the per-subscriber re-check of child rights.
  Not needed, so not done.
- **Gap that already exists:** `MessageNotifier` holds `subscribeLive` only for
  `sharedWithMe` (`components/Notifications/MessageNotifier.tsx:365-374`), so a
  conversation produces live updates and toasts only while its page is open.
  Fix in step 5: also subscribe to every conversation in `useConversations()`.
  One `SUB` per conversation per socket; fine at tens, revisit past a few
  hundred (a server-side "member feed" is the notifier work in
  `planning/notifications.md`).
- Initial load: `useChatMessages` and `useChatLogPages` run a collection with
  `property=parent, value=conversation, drive=<conversation>`. Needs the
  client fix in the table above (treat `Conversation` as its own drive scope).
  Server-side that query is served by the parent index; DID atoms reach every
  drive's filters and the stamp check keeps them apart (`db.rs:3639-3643`).
- **Reconcile (`SYNC`) is pull-only for members.** `import_sync_push` requires
  `write` on the root (`engine.rs:1801-1812` via `may_accept_drive_write`,
  `:1685`), and `handle_sync_vv_filtered`'s doc comment says `pull` stays empty for an agent
  who cannot write (`engine.rs`, above `handle_sync_vv_filtered`; **I read the
  comment, not the code path**). Members
  push through individual signed `COMMIT`s and the outbox, which the rights
  check handles per commit. That is the same as the drive design today;
  `collect_drive_subjects` (BFS on the `parent` index, no class check) means a
  member can still *pull* a conversation with `SYNC drive=<conversation>`.
  **(inferred, not run: add the test in "Tests".)**
- **Iroh / device-to-device:** peer sync is per explicitly named root
  (`sync/peer.rs:1664-1740`), and an incoming push into a root that already
  exists needs `write` on it (`peer.rs:896-905` -> `may_accept_drive_write`).
  No one has `write` on a conversation, so two devices of one agent cannot
  push conversation changes to each other over Iroh once both hold it. A
  pre-existing limit of the drive design; the root model does not change it.
  Out of scope here. Fix later with a conversation branch in
  `may_accept_drive_write` that runs the entry rules per page instead of
  blanket-importing, never a blanket `append` allowance (a raw Loro import
  bypasses the per-entry author check).
- Presence: `Store.presenceScope` (`store.ts:6865-6893`) returns the nearest
  resource with a `read` list, which for a conversation is itself. Typing and
  presence work on that channel without a drive.

## Admission: how a node decides to store a conversation

Today a root conversation is already judged by `SyncPolicy::admit_decision`
with the conversation's own subject, exactly like a drive (`commit.rs:1296-1301`),
so a gated node counts it as a drive. The change is to let the policy tell
them apart and to give it what it needs.

What the node needs (open core mechanism, no SaaS specifics):

1. **A conversation-aware enroll decision at creation.** Extend `SyncPolicy`
   (`lib/src/sync/policy.rs`) with two defaulted methods:
   - `may_enroll_conversation(&self, conversation: &str, members: &[String], creator: &ForAgent) -> bool`
     (default: `may_enroll_drive`).
   - `enroll_conversation(&self, conversation: &str, members: &[String])`
     (default: `enroll_drive`).
   In `commit.rs:1321-1332`, when `is_new` and the new resource is a
   `Conversation`, call the conversation variants with `read` as `members`.
   `OpenPolicy` (all authenticated agents) and `AllowlistPolicy` (nobody by
   asking) keep their behavior through the defaults; a control plane
   overrides them.
2. **Pages and attachments need nothing new.** They call
   `admit_decision(<conversation subject>)` already; after `enroll_conversation`
   the policy answers for the subject like any enrolled root, so the
   over-quota path (`commit.rs:1334-1339`) works unchanged.
3. **A way to list what is hosted:** `Db::conversation_subjects()`, the sibling
   of `drive_subjects()` but via the `isA` index, not a full scan. The node can
   then (a) report per-conversation usage with the existing `per_drive_usage`
   (`db.rs:1784`, root-subject based) and (b) rebuild its admission state
   after a restart. `host_mode::install_policy` (`host_mode.rs:403`) enrolls
   existing conversations too, so switching to owner mode does not lock out
   what is on disk.
4. **A distinct refusal.** `conversation_not_enrolled_message` (defaults to the
   drive text). It must keep the phrase `is not enrolled for sync on this node`
   or `local-outbox.ts:267` must learn the new one; the client then shows
   "this node does not host this conversation" instead of a drive error.
5. **What the member list means for a managed node:** the members are public
   plaintext (`read`), the creator is the genesis signer. A node can admit a
   conversation when at least one member is an account it serves and the
   conversation fits that account's allowance (count and bytes), and it must
   not count the conversation toward its drive limit. How the node learns
   which agents it serves, and what the allowance is, belongs to the policy
   implementation outside the open core.
6. **Owner mode** (`OwnerPolicy`, `policy.rs:344-420`): creator must be the
   owner, as for drives. This matches `connections/hosting.md` ("the side with
   the server creates it"). A stranger cannot open a conversation on someone's
   personal node; the owner's client creates it on accept.
7. **Bootstrap through `SYNC_PUSH`** (`admit_unknown_drive`, `engine.rs:1762`)
   has no member list and cannot tell a conversation from a drive before
   importing it. On gated policies unknown-drive bootstrap is already refused
   (`may_enroll_drive` is false for allowlist and non-owners); on an open node
   it is allowed as for any drive. So on a gated node **a conversation is
   created through `COMMIT`**, never by pushing a finished one.

Per-member byte accounting. The unit is the conversation: `per_drive_usage`
counts resources, Loro snapshot bytes and blob bytes of a root, with blobs
once per root. Charge it to the creator's allowance (the policy decides); do
not split it per member. Entries carry their author (`a`), so a per-author
split can be computed from page contents later, but it is not available to
`per_drive_usage` and is not needed for v1.

## `/conversations` and listing

- The endpoint works unchanged for a root conversation (the `read` reference
  index is class-agnostic; `plugins/conversations.rs:71-93`). A conversation
  keeps being found through `read`, the same plaintext ACL the host needs to
  authorize writes.
- Changes (step 4):
  - Put `isA == Conversation` in the query as a filter instead of filtering in
    memory, so an agent named in thousands of shared drives does not pay for
    them **(inferred: relies on the combined index from `filters`,
    `requires_query_index`, `query_index.rs:728`)**.
  - Add a `limit` (default 200) and a cursor, newest first. An unbounded list
    is the cheapest spam amplifier: anyone can name a victim as a member.
  - Return only what the requester can read (already enforced by `for_agent`).
- Client: keep the creator's `conversations` list on the private drive (it
  also records note-to-self and works offline). The Messages panel still merges
  list and endpoint (`useConversations.ts:75-102`). Add the "Requests" split on
  the client: a conversation whose creator is not a contact and shares no drive
  with you appears under Requests with no toast. The server cannot know
  contacts.
- Hosted elsewhere: not supported, as today (the endpoint says so in its
  header). `getWebSocketForSubject` sends DIDs to the home server
  (`store.ts:4897-4905`).

## Migration of existing conversation drives

Few and young. Plan: convert **in place**, on the host, by dropping `Drive`
from `isA`.

Why it is safe:

- Subject unchanged, so the keyring, every epoch and every sealed message keep
  working (`sealed_aad` binds the subject; the same bytes open under the same
  subject).
- The resources are already parentless and already hold the right ACL, and
  they are listed on `conversations`, not `drives`. There is nothing to
  un-list, move or re-parent. (Pages could not be moved anyway: moving a page
  needs `write` on it, which members do not have; a page's `parent` is also in
  its genesis certificate, `commit.rs:611`.) Verify with a count on a real
  store that none is in a `drives` list **(inferred from the comment on the
  `conversations` property and `useConversations.ts`; the migration should log
  any it finds)**.
- Children keep their `drive` stamp (the conversation), so admission, rights
  and fan-out see no difference.

Mechanism, modeled on the chat-log migration (`lib/src/db/chat_migration.rs`):

- [ ] `Db::migrate_conversation_roots()`: for each resource whose `isA`
      contains both `Conversation` and `Drive`, write a commit that sets `isA`
      to `[Conversation]`, signed by the store's migration agent with rights
      checks off (`chat_migration_agent`, `chat_migration.rs:305`). Marker
      `conversation-root-migration-v1` and a `-state` row in `Tree::PluginMeta`,
      resumable, no-op on re-run. Runs in `Db::open` next to
      `migrate_messages` (`db.rs:625-627`), native stores only.
- [ ] Browser worker: only for local-only roots this browser owns (a note to
      yourself; the registry is `atomic.localOnlyDrives`, `store.ts:1152`), flip
      the class locally in `ClientDb` init, like the message migration does for
      local-only drives. Hosted copies are replaced when the host's change
      arrives.
- [ ] Rollback is the inverse commit (re-add `Drive`); nothing else was touched.

Offline and stale devices:

- A device that was offline keeps `isA: [Conversation, Drive]` in its cache
  until it fetches the resource again. The server does not care what a client
  believes (no server path keys on the client's copy). The client code is
  written to key on `Conversation` first and `Drive` never, so a stale copy
  behaves like a migrated one.
- Queued outbox commits to the old drive (messages written offline) are
  ordinary children of the conversation and pass `check_append` the same way
  (`commit.rs:1139`); their `drive` stamp is the conversation, which the new
  admission hook enrolls.
- **Clients from before this release** open a migrated conversation as a plain
  ChatRoom-like page whose query scope falls back to the active drive and shows
  no messages (`ChatRoomView.tsx:1224`). Accepted: few and young conversations,
  and the app updates itself. To keep the window short, ship client (step 2)
  and server migration (step 3) in consecutive releases, not the same one: the
  client is tolerant of both shapes first.
- New client against an old server: a server without step 1 still grants the
  creator `write` at genesis. The client therefore keeps the defensive
  `remove(write)` + second save when `write` is present after the first save,
  and does nothing when it is not. Delete that after one release.
- Managed nodes that enrolled a conversation as a drive (because creation
  needed it): the control plane should drop that drive enrollment for a subject
  the node now reports as a conversation, so the drive count falls. The node's
  side is `conversation_subjects()`; the control plane's side is outside this
  repo.
- DMs as entries (step 6): `SealedMessage` -> entry copies the `sealed` value
  **verbatim** into field `s` (same conversation subject, so the same AAD and
  nothing is re-sealed). A device whose message is still in the outbox as a
  `SealedMessage` resource keeps working: the reader merges both shapes by time
  exactly as it does for `Message` resources (`chat-log.md`, "Existing
  messages").

## Keyring and epochs

- The keyring (`conversationKeys`) is a property of the root conversation and
  is unchanged: one random key per epoch, wrapped to each member's
  `encryptionKey`; each sealed message's header names its epoch. Moving from
  Drive to root changes none of that.
- **Members cannot change yet.** With `write` for nobody, neither `read`/`append`
  nor the keyring can be edited by anyone, so no member can be added and the
  epoch cannot be rotated. Same limit as today; this design does not make it
  worse and makes the fix cleaner, because the conversation now holds only
  keyring and ACL, no messages.
- The rule that lifts it (not in this plan, recorded so the design stays open):
  a commit on a `Conversation` by a member (`append`) that only appends an
  epoch to `conversationKeys` (existing epochs byte-identical) and changes
  `read`/`append` so that they equal the newest epoch's wrapper set. The server
  can check this because the ACL and the keyring's member list are plaintext.
  Pair it with: `write` inherited from a `Conversation` does not count as
  "writer of the chat" for entry edits in `check_chat_log_member_commit`, so
  nobody can ever rewrite another member's entries.
- Leaving: a member cannot remove themselves server-side (no `write`). The
  avatar PR's client-side hide list is the stopgap; a self-removal rule belongs
  with the member-change rule above.

## Spam and abuse limits

Anyone can name anyone as a member, and the named person cannot refuse
server-side. So limits have to bite at creation, on listing, and on the
recipient's screen.

| Limit | Where | Default |
| --- | --- | --- |
| Conversations created per signer | New bucket next to `WriteRateLimiter` (`server/src/rate_limit.rs`), consulted for a `Conversation` genesis in `handlers/commit.rs` and the WS `COMMIT` path (`handlers/web_sockets.rs:551-561`) | 20 per hour, 200 per day |
| Members per conversation | Genesis check in `commit.rs` | 32 |
| Conversations per signer per node | Policy hook (`may_enroll_conversation`) | Open nodes: 1000. Managed: the account allowance. |
| Bytes per conversation | Policy quota (`drive_within_quota` path, `commit.rs:1334`) | None on open nodes; managed: allowance |
| `/conversations` size | Endpoint | 200 newest, with cursor |
| Recipient screen | Client: Requests for unknown creators, no toast or badge until accepted; hide list for blocked | Requests by default |
| A recipient with no `encryptionKey` cannot be messaged | Already so: `memberFor` throws `NoEncryptionKeyError` (`conversations.ts:72-84`) | Unchanged; natural friction |
| Entry flood inside a conversation | Existing per-agent write rate limiter on `COMMIT` (`web_sockets.rs:551-561`) and the byte quota | Unchanged |

## Local-only note-to-self

A note to yourself is a conversation with `read == [me]` that never leaves the
device (`conversations.ts:101-105`, `:149`). The root model keeps it as is:
`registerLocalOnlyDrive(subject)` is keyed on the subject, not the class
(`store.ts:1152`), and pages inherit through their `drive` stamp
(`isLocalOnlySubject`, `store.ts:1481-1500`). Keep:

- the `hasMembers(conversation, [me])` exception in `healRefusedDrive`
  (`refusedDrive.ts:39-44`), because the new admission hook may still refuse a
  note-to-self on a node that does not serve you, and the right answer is then
  to keep it browser-only;
- the genesis rule "signer is in `read`" (one member is allowed), so a
  note-to-self stays valid if it is ever promoted to a server.

## Tests, cheapest layer first

Rust unit (`lib/tests/conversation_root.rs`, patterned on `lib/tests/chat_log.rs`):

- [ ] Genesis of a root `Conversation` gets no automatic `write`; a second
      commit is not needed.
- [ ] Genesis with `write`, with a `parent`, with more than 32 members, with
      the signer not in `read`, or with `append` outside `read` is refused.
- [ ] No one (creator included) can change `conversationKeys`/`read`/`append`.
- [ ] A member creates a ChatLog page under it; an outsider cannot; a member
      cannot edit another's entry; the creator cannot either.
- [ ] `Resource::get_drive()` is the conversation's own subject.
- [ ] Policy: a test policy that refuses `may_enroll_conversation` gives
      `NotEnrolled` for the conversation genesis and for nothing else; after
      `enroll_conversation` pages are admitted by subject; `OwnerPolicy`
      admits only an owner-created conversation; `conversation_subjects()`
      returns only conversations and `install_policy` enrolls them.
- [ ] Migration (`lib/src/db/conversation_root_migration_test.rs`): `Drive`
      class dropped, keyring and ciphertext bytes identical, a sealed message
      still opens with `conversation::open_message` under the same subject,
      re-run is a no-op, resumable after a stop, a conversation drive with a
      non-conversation sibling is untouched.
- [ ] `collect_drive_subjects` on a non-Drive root returns its pages; a member
      `SYNC` pulls them; a member `SYNC_PUSH` into an existing conversation is
      refused (documents the Iroh limit above).

Rust integration (`server/tests/it/conversations.rs`, real server, extend the
existing two tests):

- [ ] `/conversations` returns a root conversation, honors limit and cursor,
      and excludes drives that merely list the requester.
- [ ] A WS `SUB` on a root conversation delivers a page commit and an entry
      update to a member and not to an outsider (the parent-subscriber path in
      `commit_monitor.rs:681-720`).
- [ ] The creation rate limiter refuses the 21st conversation in an hour.

`browser/data-browser` unit (vitest): `conversations.test.ts` (created without
`Drive`, one save, defensive `write` drop only when `write` is present),
`useChatMessages` scope for a root conversation, `refusedDrive.test.ts`
unchanged, `conversationsEndpoint.test.ts` for the new paging params.

`browser/lib` integration (`browser/lib/tests/`, real server, two agents):

- [ ] Alice creates a root conversation naming Bob; Bob's store gets a page
      entry live through `subscribeLive(conversation)` with no drive
      subscription; Carol cannot read or subscribe.

One Playwright test: extend `browser/e2e/tests/conversations.spec.ts` ("two
people message each other, encrypted") to also assert that the conversation
does not show in the drives list and `store.getResource(subject)` is not a
`Drive`. No new spec; no `@smoke`. Update `TESTING_COVERAGE.md`.

## Build order: small PRs

Sizes are rough diff sizes including tests.

1. [ ] **Server rules for a root `Conversation`** (S/M, ~250 lines). Genesis
       checks, no automatic creator `write`, `get_drive()`, ontology text and
       `requires`. Rust unit tests. Behavior of existing drive-shaped
       conversations is unchanged.
2. [ ] **Client creates root conversations** (S/M, ~150 lines). No `Drive` in
       `isA`, one save with a defensive `write` drop, drive-scope fixes in
       `collectionBuilder.ts`, `ChatRoomView.tsx`, `presenceScope`, copy in
       `ConversationPage`. Tolerates both shapes.
3. [ ] **In-place migration** (M, ~300 lines). `Db::migrate_conversation_roots`,
       worker flip for local-only roots, migration tests. A release after 2.
4. [ ] **Admission hook and listing** (M, ~300 lines). `SyncPolicy` methods,
       `commit.rs` branch, `conversation_subjects()`, owner-mode enrollment,
       refusal text and client matcher; `/conversations` filter, limit, cursor.
5. [ ] **Abuse limits and live** (M, ~250 lines). Creation rate limiter, member
       cap config, Requests split in the Messages panel, `MessageNotifier`
       subscribes to every listed conversation.
6. [ ] **DMs as ChatLog entries** (L, ~600 lines; skip if it lands elsewhere).
       Sealed entries (`s`), `sendSealedMessage` through `appendToChatLog`,
       reader merge of `SealedMessage` children and entries, verbatim
       `SealedMessage` -> entry migration. Follows `chat-log.md` step 4.
7. [ ] **Docs and coverage** (S). Update `planning/encrypted-conversations.md`
       ("Model": root, not drive; live updates), the DM row in
       `planning/chat-log.md`, `TESTING_COVERAGE.md`, and the e2e assertion.
       The `planning/README.md` index entry is added by whoever opens the PR.

Later, not in this plan: member change and epoch rotation, self-removal,
conversations hosted on another server, Iroh push into a conversation,
per-author accounting.

## Open questions for Joep

1. **Convert in place instead of re-publishing?** Your brief said re-publish
   and move the pages. Pages cannot be moved by members and ciphertext is bound
   to the subject, so I propose dropping the `Drive` class on the host and
   changing nothing else. *Recommended: in place.* Costs: clients older than
   step 2 briefly show an empty conversation.
2. **Order of DMs-as-entries (step 6).** Before or after the root change?
   *Recommended: after* (root first, steps 1-5), because the root change is
   small and unblocks the managed-node problem now; the sealed payload moves
   verbatim later.
3. **Who is charged on a managed node.** The creator's allowance, or every
   enrolled member's. *Recommended: the creator's,* with the conversation
   refused if the creator is not served by that node. It matches
   `connections/hosting.md` (the side with the server creates) and avoids
   splitting bytes. A one-directional spammer still burns only their own
   allowance.
4. **The limits.** 32 members, 20 conversations per hour and 200 per day per
   signer, 1000 conversations per signer on an open node, `/conversations`
   capped at 200. *Recommended: ship these numbers as constants first,* make
   them config later.
5. **Self-removal and member changes.** Ship none of it now (members stay fixed
   and a recipient can only hide a conversation client-side), or add the
   self-removal rule in step 5 so a named person can leave server-side?
   *Recommended: not now.* It belongs with the member-change and epoch-rotation
   rule, which needs its own design.
