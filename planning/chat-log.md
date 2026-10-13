# Chat log: messages as entries, not resources

> **Status:** Design (2026-10-09). Joep chose this route ("Chatlog (D)") after
> the measurements in [`chat-message-storage.md`](./chat-message-storage.md).
> Steps 1 (class, entries, server rule, tests) and 2 (group chat and comments)
> are built, and so is the migration of existing messages and the follow events
> (see "Existing messages"). Step 3, AI chat, is built with its migration (see
> "Step 3: AI chat").

## Why

A chat message is now a resource of its own. On develop it stores 3.3 KB of
rows (commit row, message row, snapshot delta, two indexes, search) and grows
the redb file by 6 to 7 KB, because B-tree pages sit half full. A message is a
few dozen bytes of text.

Prototype (Loro 1.12 via the Python binding, three authors, one Loro change per
message, snapshot deflated):

| entries per log | "hallo" | 48-character sentence |
| --- | --- | --- |
| 50 | 47 B | 57 B |
| 256 | 37 B | 46 B |
| 1000 | 37 B | 46 B |

Add about 12 B per message for the page resource around them (3 KB per 256
messages). So about 50 to 70 B per message, against 6 to 7 KB now: roughly a
hundred times smaller. Ordinary commits are already discarded after apply and
only the latest envelope per resource is kept, so the per-message commit adds
nothing lasting.

## Model

- **`ChatLog`** is a new class: one page of a chat, a child of the chat
  (`parent`). A page holds up to 256 entries; the client appends to the newest
  page that has room and creates a new page when it is full. Two clients that
  both create the next page give two pages, which is harmless: the reader merges
  pages by entry time.
- Entries live in a Loro root map **`entries`**, next to `properties` and
  `datatypes`. They are not materialized into propvals and get no index rows,
  so the page's resource row and indexes stay the size of an empty resource.
- **Entry key:** `<createdAt ms, hex>-<8 random hex>`, so keys sort by time.
- **Entry value:** a plain Loro map value (not a container), replaced whole on
  edit:
  - `a` author agent, `t` text (markdown), `c` createdAt (ms), optional
    `r` reply-to entry key, `e` edited-at, `k` extra kinds (`FollowEvent`).
  - AI chat: `role` and `parts` (the parts that are now child resources).
  - DMs: `s` the sealed payload instead of `t`.
- **Delete:** remove the key.
- **Link to one message:** `<page subject>#<entry key>`.

## Rights: append-only per author

In one document every member would otherwise be able to rewrite every message,
which today only `write = [author]` per message prevents. The server enforces
it per commit:

1. Creating a page needs `append` on the chat (the existing `check_append`).
   A page does **not** give its creator `write` at genesis, unlike other DID
   resources.
2. A commit by a signer **without** `write` on the page (inherited `write` on the
   chat counts, so moderators keep full control) is accepted only if:
   - `properties` and `datatypes` do not change (except at genesis), and
   - for every key in `entries` that the update adds, changes or removes, the
     entry before (if any) and after (if any) has `a` equal to the signer.
3. The check reads `entries` before and after the import, the way
   `import_update_with_diff` already does for `properties`
   (`lib/src/loro.rs`), and rejects before anything is stored.
4. `c` is client time. The server rejects entries whose `c` is more than ten
   minutes ahead of its clock; older times are allowed (offline sending).

Rules added while building step 1:

- A member commit also needs `append` on the page (inherited from the chat),
  and cannot destroy a page.
- Changes to `lastCommit` and `createdAt` are ignored in the "properties
  unchanged" check: clients can carry stale ops for them and changing them
  gives a non-writer nothing.
- At genesis, a creator without `write` on the chat cannot set `write` on the
  page; otherwise a member could mint a page only they can rewrite.
- The ten-minute future check applies to writers and to genesis as well.
- The server does not restamp `lastCommit` on later commits to a page (genesis
  keeps its value). The stamp is a ~100 byte incompressible string written as
  its own Loro change; it tripled the cost of a message.

## Measured (step 1)

500 entries, one signed commit each, pages of 256, stable client peer,
42-character text (`measure_chat_log_entry_bytes`): 64 B per message in total,
of which 46 B snapshot, 9 B resource row, 3 B envelope, 5 B index keys, no
search rows. Existing `Message` resources: 3285 B. With the `lastCommit`
restamp it was 201 B.

## The chats

| chat | parent of the pages | notes |
| --- | --- | --- |
| Group chat | the `ChatRoom` | replaces `Message` with `parent` |
| Comments | the drive's comments folder, page has `about` = the item | one log per commented item, found by `about` (one index row per page, not per comment) |
| AI chat | the AI chat | single author; a message and its parts become one entry, the biggest win per message |
| DMs | the `Conversation` | entries carry the sealed payload; members already have only `append` |
| Follow events, meeting toasts | the follow-sessions `ChatRoom` | they are `Message`s today, one per visited page |

Notifications (`Notification` per message in the inbox) are the other
one-resource-per-event data; they can become an inbox log later, same design.

## What stays the same

- Live updates: a page is an ordinary resource, so its commits fan out as Loro
  deltas over the existing `SUB`/`UPDATE` path; WS and Iroh sync need nothing new.
- Search: the page's search document is the text of its entries; a hit opens
  the page and scrolls to the entry. No per-entry index.
- Mentions, replies and edit keep their UI; they read and write entries.

## Existing messages

Old `Message` resources are moved into the log, and the old resources are then
removed. Decisions (Joep, 2026-10-09):

1. **Scope.** Every `Message` resource: group chat, comments, meeting chat and
   FollowEvents. Not `SealedMessage` (DMs) and not AI chat yet.
2. **Grouping.** By `(parent, about)`. Inside a group the messages sort by
   `createdAt` and fill pages of 256, the same page shape the app writes
   (`ChatLog`, `parent`, `about` for comments, entries in `entries`). Entry `a`
   is the message's original author (`createdBy`), `t` the description, `c` the
   `createdAt`, `k` FollowEvent when the class is there, `e` when it was edited
   (a retained commit more than a second newer than the creation). `r` is the
   new `<page>#<key>` id when the replied-to message is migrated too, else the
   old subject.
3. **Deterministic key.** `<createdAt hex>-<first 8 hex chars of SHA-256 of the
   old subject's id>` (the part after `did:ad:` / `atomic:`, no query or
   fragment: `migrated_entry_key` in Rust, `migratedEntryKey` in TS, one shared
   test vector). A re-run, a second migrating peer or a stale cached copy can
   recognise a migrated message by it. The reader hides an old `Message`
   resource whose key exists in a loaded page of the same chat, and lists one
   entry key that sits on two pages once.
4. **Authority.** The pages are signed by an agent that belongs to the store
   (made on first use, kept in `Tree::PluginMeta`) and written with rights
   checks off, like a server-internal write. The author of an entry is
   attested by the host; the original per-message signature is not carried
   over. The page creator gets no `write`, so the normal rule for later commits
   holds: members only change their own entries, writers of the chat all.
5. **Removal.** After a group's pages are written, the old resources go:
   resource row, Loro snapshot, envelopes, genesis commit row, index and search
   rows (`remove_resource`, which also leaves a tombstone so a stale peer cannot
   bring them back). Old message URLs then 404. Order matters for a crash: pages
   first, removal second; a restart finds the entries by key and only removes.
6. **Where it runs.** Resumable, marker `chat-log-migration-v1` (and a
   `-state` row with `done`, `total` and the list of groups) in
   `Tree::PluginMeta`, in slices of whole groups, progress `done/total`:
   - Server and other native stores: `Db::open` after the index migration and
     the bootstrap, logged (`Db::migrate_messages`; the AI chats follow in `Db::migrate_ai_chats`, see step 3).
   - Browser worker: `ClientDb` init, after the index rebuild, with progress on
     the existing upgrade notice (`phase: 'messages'`). The page passes the
     drives that exist only in this browser (`atomic.localOnlyDrives`, the
     registry `Store.registerLocalOnlyDrive` keeps); only for those the worker
     writes pages. For every other drive (hosted by a server) the server makes
     the pages and the worker only deletes cached `Message` rows whose key is
     in a local ChatLog page. Nothing in the registry (empty, unreadable,
     private window) means cleanup only: the safe side. A cache that gets its
     pages after the migration ran is cleaned when the next version opens the
     store; until then the reader's hiding rule (3) covers it.
7. **New follow events and meeting messages** are entries (`k` FollowEvent),
   written by `sendChatMessage` through `sendLogEntry`. No `Message` resource is
   created by the app any more (the demo workspace's persona messages still are:
   they cannot be signed as a persona).

Known leftovers: an edited old message whose genesis commit row cannot be reached
(no `lastCommit` or retained envelope pointing at it) keeps that row, about 1 KB;
a tombstone costs about 100 B per migrated message in `PluginMeta`.

## Build order (one PR each)

1. `atomic_lib` and `@tomic/lib`: `ChatLog` class, entry read/write helpers
   (Rust and TS), the server rule with tests (author can add, edit and delete
   own entries; cannot touch others'; moderator can; page genesis grants no
   write; future `c` rejected). Storage measured with
   `measure_chat_message_bytes` adapted to the log.
2. Group chat and comments, with the merged reader and pagination per page.
3. AI chat.
4. DMs.
5. Follow events and meeting toasts (built with the migration of existing
   messages).

## Step 2: group chat and comments (as built)

- **Writing.** `appendToChatLog` (`helpers/chatLog.ts`) finds the pages of a chat
  (collection query on `parent` of the ChatRoom, or `about` of the commented
  item, `isA ChatLog`), adds the entry to the newest page when it holds fewer
  than 256 entries, and otherwise creates the next page (with the first entry in
  it, in one commit). Sends to one chat run one after another, and pages this
  client made are remembered, so a quick second message or an offline one does
  not start a second page. Comments: page `parent` is the drive's comments
  folder, `about` the item, one log per item.
- **Reading.** `useChatMessages` keeps the same shape (a list of ids, "show
  older", the `chat-tail:` cache) but an id is either an old `Message` subject
  or an entry id `<page subject>#<entry key>`, the same string the copy-link
  button copies. The list is the newest `visible` of both merged by time
  (`windowChat`): old messages by their creation time, entries by `c`. Pages are
  loaded newest first until the window is full.
- **Live.** Entries are not properties, so `useChatLogRevision` subscribes to
  the loaded pages (`store.subscribe`, plus the resource's `LocalChange` for
  entries added in this tab) and re-reads on every change.
- **Edit/delete.** Own entries only, in the UI. Edit replaces the value and sets
  `e`; the reply stays. Old `Message` resources keep the generic edit form.
- **Reply.** `r` holds the entry id (`<page>#<key>`) rather than the bare key,
  because the quoted entry can be on another page. An old message is its
  subject. The composer clears its reply state when the message is submitted,
  not when the server answers: the message shows at once now.
- **Counts and unseen.** `useCommentCount` is old `Message`s plus the entries of
  the item's pages. Unseen compares that total with the number marked seen.
- **Notifications.** `MessageNotifier` also listens to updated ChatLog pages and
  treats each entry that is new since the app started and not the viewer's as a
  message (`entryFacts`); one handled set keyed by entry id keeps edits and
  repeated updates from announcing twice. Reply authors are looked up on the
  entry's page.
- **Opening a page.** A ChatLog page has no view of its own: opening it (the
  parent of a copied link) redirects to the chat, or to the item with the
  comments open.
- **Not in the log yet.** DMs are untouched (AI chat: see step 3). Meeting chat messages
  typed by people are entries (it is a ChatRoom); the meeting toaster reads both.
  Follow events became entries with the migration of existing messages.

Choices to revisit:

- The "show older" count is exact for loaded pages. Pages that are not loaded
  yet count as one message each (a page is never empty), so the number is a
  lower bound until they load.
- Scrolling to the linked entry is not built: the app's URL has no place for
  the `#<key>` of a link, so opening one lands on the chat.
- Comments (log or not) live in the drive's comments folder, so only people
  with access to the drive see them; a guest invited to a single item sees no
  comments. Unchanged from `Message`s.

## Step 3: AI chat (as built)

- **Shape.** The AI chat resource stays (name, `about`, emoji). Its messages
  are entries of `ChatLog` pages whose `parent` is the chat. An entry is one
  whole message: `a` the author agent, `t` empty, `c`, `role` (`user`,
  `assistant`, `system`, `summary`), `parts` the parts as a JSON string, as the
  UI message holds them (text and reasoning `{type, text}`, `file`,
  `source-url`, tool calls in the normalized form `restoreToolPart` produces:
  `type: "tool-<name>"`, `toolCallId`, `state`, `input`, `output` or
  `errorText`), `ctx` the provided context as a JSON string (atomic and MCP
  resources; skills are not stored, as before), `sc` the server provided
  context, `err` why a reply stopped. `ai-chat.messages` is no longer written.
  Code: `chunks/AI/aiChatEntries.ts` (message <-> entry),
  `chatConversionUtils.ts` (writes, removes, reads).
- **Writes.** `addMessageToChatResource` appends to the newest page that has
  room or makes the next one (`parent` the chat). A checkpoint of a streaming
  reply, a retry or a regenerate re-saves the same message by putting the same
  entry key with its first `c`: nothing moves. `c` of a new entry is the larger
  of now and one more than the newest `c` this client knows, so two messages in
  one millisecond keep their order. Removing one message, or all after one
  (regenerate, delete-following) removes entries, a page save per page. All
  writes of a chat, removals included, run on the chat's one queue
  (`queueChatWrite`), so a checkpoint in flight cannot bring back an entry that
  was just removed.
- **Draft chats** (planning/ai-chat-draft-persistence.md). While the chat is a
  draft its page is only local; the finalisation sweep saves the page(s) before
  the chat, as it did for the message resources.
- **Reading.** `loadChatMessages` lists the pages of the chat, merges their
  entries by `c` (not by key: migrated keys carry the old creation time while
  `c` was raised to keep the list's order) and merges old `ai-message`
  resources that have no entry yet (hidden when their deterministic key is in a
  page, as for `Message`s). The display message id is the entry id
  `<page>#<key>`.
- **Migration** (`lib/src/db/ai_chat_migration.rs`). Same mechanism as the
  `Message` migration: its own marker `ai-chat-log-migration-v1` and `-state`
  row in `Tree::PluginMeta`, whole chats per slice with `done/total` in
  messages, `Db::open` on native stores (after the `Message` migration), the
  browser worker after it (same upgrade notice, same local-only versus hosted
  rule: hosted drives are only cleaned of cached rows that have their entry).
  Per chat: the order is the `messages` list, not `createdAt`; `c` is the
  creation time raised to one millisecond after the entry before it. Entry key
  = `migrated_entry_key(createdAt, subject)`. Pages of 256 entries are written
  first, then each old message goes together with its part resources and its
  `mcp-resource` context items, then `messages` is cleared on the chat (signed
  by the migration agent). A restart in between finds the entries by key.
- **Page size counts entries, not bytes.** An AI message can carry large tool
  outputs, so 256 messages is not a bounded page the way 256 chat lines are.
  No byte cap was added: a page is one Loro document and a commit rewrites
  only the delta, so the cost is in loading a page (the chat loads every page
  anyway) and in the first sync of it. If big outputs turn out common, the
  cheap fix is a smaller entry count for AI pages (the page choice already
  takes a capacity), or storing outputs above a size as a file and keeping a
  reference in the part. Decide with measurements from real chats.
- **Measured** (`migrating_an_ai_chat_shrinks_the_store`, 20 messages, half of
  them assistant messages with a reasoning part, a text part and three tool
  calls with a 12-row result): 43.5 KB per message as resources, 1.8 KB per
  message after (1,941,584 B to 1,107,362 B on a 1,071,006 B baseline). What
  remains is mostly the tool results themselves and the tombstones.
- **Not changed.** The chat list (`AIPanel`, `findLatestAiChatAbout`) reads the
  AI chat resources, not messages. The summary role and
  `CompactSeparatorWidget` work on UI messages, so they are untouched.

## Open questions

- Page size 256: small enough that loading the newest page is instant, large
  enough that the page overhead stays near 12 B per message.
- Reactions do not exist yet. They cannot live inside the entry, which only its
  author may change; they would be entries of their own (`k` reaction, `r` the
  target), so the same rule covers them.
