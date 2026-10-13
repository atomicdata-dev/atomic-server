# Notifications

Status: **Server delivery proposal, updated 2026-10-08.** Client recording,
grouping and read state exist. Client sync/pagination/identity fixes and browser
regressions are pending in PR #2130. The server notifier, following and closed-app
push below remain proposed.

## Current client recording

Today the recipient's own open app decides what is news. `MessageNotifier`
listens to `ResourceUpdated` for `Message` resources and writes a
`Notification` into the Inbox of the private drive. That has limits that no
client change can remove:

- **The selected workspace and explicitly shared conversations notify.**
  `MessageNotifier` holds live subscriptions for `sharedWithMe`; the personal
  drive subscription in PR #2130 keeps Inbox and read state current independently
  of the selected project. Other inactive project drives still need a delivery
  policy and source subscription or the server notifier.
- **Nothing is recorded while every app is closed**, so the Inbox has gaps and
  push has nothing to send.
- **Several open devices each record the same event**, and dedupe afterwards.
- **Most events worth telling someone about are not messages**: being given
  access, someone accepting your invite, a new row in a table you care about,
  a meeting starting. The app of the person concerned usually never sees them.

So the server should decide who is told what, and deliver it into the
recipient's Inbox. The client keeps showing it: toast, OS notification,
Notifications page.

## Remaining acceptance work

- [ ] Deliver an Inbox item while every recipient app is closed. The October 8
  local diagnostic confirmed a new message was readable after restoration but
  missing from the Inbox. Replaying every old message as a new toast is not an
  implementation of durable delivery.
- [ ] Implement the server after-apply notifier and constrained Inbox append
  authorization below. Keep recipient keys on their devices; use a server-signed
  append grant and recheck recipient access before delivering titles/excerpts.
- [ ] Make delivery retry-safe across restarts and reconnects; test duplicate
  source events, read updates during delivery, revoked access and an inaccessible
  or differently hosted personal drive. Negotiate the server capability before
  disabling the existing client recorder.
- [ ] Notify from incoming Inbox records for notifier-capable servers. Today
  toasts still originate from source Messages, so a durable Inbox alone does not
  establish foreground or OS announcement.
- [ ] Verify real native permission, receipt and click activation on macOS and
  Android. The pinned Tauri Notification polyfill submits to the plugin but does
  not wire `onclick`; the browser service-worker fallback has neither target data
  nor a `notificationclick` handler. A fake window.Notification cannot accept
  these paths.
- [ ] Cover failed OPFS initialization separately from the deliberate Local DB
  off mode, which now has notification reconnect coverage on PR #2130.

The implemented client regressions are mapped in
[`TESTING_COVERAGE.md`](../TESTING_COVERAGE.md#notification-pagination-identity-and-server-only-mode-october-8-2026).

## Model

### Delivery: the server appends to the Inbox

- The Inbox (`notifications:inbox` on the private drive) gets
  `append: [<server agent>]`, `read` and `write` stay the owner's. This is the
  constrained append-only inbox from
  [`authorization-sync.md`](./authorization-sync.md#constrained-append-only-inbox-first-contact-and-bridges),
  granted to the server rather than the public. Servers that predate this keep
  the client-side recording from #1859 as a fallback.
- A **server notifier** runs as an after-apply hook (the `after_commit` path of
  `ClassExtender` in `lib/src/db.rs`, but for every applied commit rather than
  per class). For each commit it computes recipients and kinds, and creates or
  updates a `Notification` in each recipient's Inbox, signed by the server
  agent.
- The recipient must be able to read the thing the notification is about.
  Rights are checked at delivery time, so a notification never leaks a title
  or excerpt the recipient could not open.
- **Only Inboxes this server hosts** (decided 2026-09-28: skip the rest for
  now). Recipients whose private drive lives elsewhere, or only on their
  device, get nothing from this server; cross-server delivery is the same
  append, sent as a commit to the other server, later.

### Following: who cares about what

Following does not exist yet; this is new. A per-person, private list of what they follow, stored in their own private
drive (a `following` array on the Inbox) and indexed by the server into a
reverse map `resource → followers`. Nothing on the followed resource reveals
who follows it.

Each follow has a level:

| Level | Tells you about |
| --- | --- |
| **Everything** | new children, changes, messages and comments |
| **New items** | new children only (a table's rows, a folder's files) |
| **Mentions only** | only when you are @mentioned or replied to |
| **Muted** | nothing, not even what an ancestor follow would send |

A follow covers descendants: following a folder at *New items* tells you about
new resources anywhere below it. The nearest follow wins, so *Muted* on one
chat inside a followed drive silences just that chat.

You follow automatically, at a sensible level:

- what you create: *Everything*
- a chat you post in, a document you comment on: *Everything*
- a resource or drive you are given access to: *Mentions only*
- a meeting you are invited to or join: *Everything* until it ends

A Follow button (bell) in the resource's top bar shows and changes the level.

### Notification, extended

`Notification` keeps its properties and gains:

- `notificationCount`: how many events this item stands for.
- structured fields instead of baked text: `notificationKind`, `actor`,
  `about`, `notificationSource`, plus an excerpt in `description`. The client
  writes the headline at display time, in the reader's language and with
  current titles. `name` stays as a plain-text fallback for other clients.

**Batching.** Nothing about edits is sent per commit (decided 2026-09-28:
every change, but no spam). The notifier queues `changed` and `created`
events per recipient and resource (for `created`: per parent) in a tree of its
own, so a restart loses nothing, and delivers once the resource has been
quiet for 10 minutes, or at the latest an hour after the first queued event.
One delivery is one notification: "Sanne and Polle edited Roadmap (12
changes)", "Sanne added 8 rows to Tasks". Messages, mentions, replies,
access and meetings are not queued: they are conversations or time-bound.

**Coalescing.** While a notification is unread, a new event with the same
`about` and `kind` updates it (count + 1, newest excerpt, `occurredAt` moves
up, `actor` becomes the latest) instead of adding a row. So five messages in
Team chat are one row, "Sanne and Polle: 5 new messages in Team chat", and a
burst of edits is "Sanne edited Roadmap (12 changes)". Once read, the next
event starts a new item.

## Kinds

| Kind | Who is told | Trigger | Opens |
| --- | --- | --- | --- |
| `chat` | followers of the chat room (not *Mentions only*) | new `Message` with a chat room parent | the chat |
| `reply` | the author of the message replied to | `replyTo` set | the chat or the comments panel |
| `comment` | followers of the commented resource | new `Message` with `about` | the resource, comments panel open |
| `mention` | the mentioned agent, if they can read it | an agent mention added to a message, document or comment | the place of the mention |
| `access-granted` | the agent added | an agent added to `read` or `write` of a resource | the resource |
| `invite-accepted` | the signer of the invite | `/invite` POST accepted | the resource, with who joined |
| `access-request` | agents with `write` on the resource | new `AccessRequest` (below) | the request, with Allow and Deny |
| `access-answered` | the requester | the request is allowed or denied | the resource, or the reason |
| `created` | followers at *New items* or *Everything* of an ancestor | new resource | the new resource |
| `changed` | followers at *Everything* | a commit changing a followed resource, by someone else | the resource |
| `meeting-started` | everyone with read access to the drive, and invitees | `meetingStartedAt` set | the meeting, joining the leader |
| `meeting-invite` | the invited agents | added to `meetingAttendees` | the meeting |
| `meeting-reminder` | attendees | scheduled time minus 5 minutes | the meeting |
| `meeting-minutes` | attendees | `meetingEndedAt` set | the minutes |

Nobody is notified about their own actions, and `FollowEvent` trail messages
("Viewing …") never notify.

### Invites and access

- **Shared with you.** Adding an agent to `read` / `write` is already a commit
  the server applies; the notifier diffs the rights and tells each added agent.
  Today the invitee only learns about it if someone sends the link.
- **Your invite was used.** Invite links are bearer tokens not bound to a
  person (`server/src/invite_token.rs`), so the only one who can be told is the
  signer: "Polle joined Roadmap with your invite link".
- **Access requests** are new. The "no access" screen gets **Request access**,
  which creates an `AccessRequest` (`target`, `requestedRight`, optional
  `message`) in the requester's own private drive and delivers
  `access-request` to everyone with `write` on the target. Allow adds the
  right (and the requester gets `access-granted`); Deny sends
  `access-answered`. Rate-limited per requester and target.

### Meetings

Meetings today have no attendees and no scheduled time
(`lib/defaults/meeting.json`); starting one only posts a `FollowEvent` into
the drive chat and adds it to `currentMeetings`. Proposed:

- `meetingAttendees` (agents) and `meetingScheduledAt` (timestamp) on
  `Meeting`. Adding someone sends `meeting-invite`; the server scheduler
  (`server/src/plugins/scheduler.rs`) sends `meeting-reminder`.
- Starting a meeting notifies attendees and everyone with access to the
  drive (decided 2026-09-28), except whoever muted the drive. A
  meeting-started notification is **urgent**: it shows as a toast even on the
  page you are on, and as an OS notification with a Join action.
- When it ends, attendees get the minutes.
- Imported calendar events (Google Calendar integration) can become scheduled
  meetings later; out of scope here.

## Client

- **Listen to the Inbox, not to messages.** The client subscribes to the Inbox
  resource on its private drive regardless of which drive is open, and shows
  a toast or OS notification for each new or updated unread `Notification`.
  One code path for every kind, and no device writes duplicates.
  `MessageNotifier`'s own recording stays only for servers without the
  notifier.
- **The unread count in the account menu** (#1915), next to its
  Notifications entry. No separate bell in the top bar: it would show the same
  number twice.
- **Grouped rows** from `notificationCount`, headline written at display time.
- **Reading.** Opening the thing reads its notifications, and so does coming
  back to the window while already on it.
- **Asking for OS permission in context**, the first time something arrives
  while the app is in the background: a toast on return saying "You missed 2
  messages while away. Show them as system notifications?", instead of only
  a checkbox in Settings.
- **Settings per kind** (chat, mentions and replies, access, changes,
  meetings), stored on the Inbox so they apply on every device; the per-device
  OS switch stays.

## Local-first FOSS and hosted

One notifier, in both. It lives in `lib`, next to commit apply, not in a
hosted-only service, so a self-hosted atomic-server computes exactly what
atomic.place computes. Notifications are ordinary resources in the person's
own private drive: there is no separate notification database, and moving
your drive to another host takes your Inbox and follows with it. The FOSS
release depends on nothing hosted; hosting only adds delivery channels.

| | Self-hosted FOSS server | atomic.place |
| --- | --- | --- |
| Notifier, Inbox, follows, batching | yes | yes, same code |
| Toast and OS notification while the app is open | yes | yes |
| Web Push when closed (browsers, desktop app) | yes, with the server's own VAPID keys; no account anywhere | yes |
| Android push when closed | only through a configurable push gateway (for example UnifiedPush / ntfy); FCM credentials belong to the official build | FCM |
| Email (digest of unread, or instant for access requests) | a hook the notifier calls; no mailer in the server | sent by the hosting layer |

**Local-only and offline.**

- A drive that lives only on your device (`registerLocalOnlyDrive`) has no
  server to run the notifier, and usually nobody else writing to it. When
  others do reach it (peer sync), the client applies their commits, so the
  client runs the same rules: that is #1859's client-side recording, kept for
  drives whose host does not run the notifier. A host announces that it does,
  and the client then stops recording for its drives, so nothing is written
  twice.
- Offline, nothing is lost: the server keeps writing your Inbox, and on
  reconnect the client syncs it like any other resource. What arrived while
  you were away is summarized once ("12 new notifications") instead of
  replayed as a burst of toasts.
- Read state is a property on the Notification, so reading on one device
  reads it everywhere, online or after the next sync.

## Push and email

With the server writing the Inbox, push is "send the new Notification to the
recipient's registered devices". Device registrations live in the private
drive. What each deployment can use is in the table above.

## Phases

1. **Client polish on today's model.** Reading on window focus, grouping,
   headline at display time, OS permission in context.
   Small, independent of the server.
2. **Server notifier, Inbox append and live Inbox subscription.** Kinds `chat`,
   `reply`, `comment`, `mention`, `access-granted`, `invite-accepted`,
   `meeting-started`. Auto-follows only; no follow UI yet.
3. **Follow button and levels.** Kinds `created` and `changed`, muting.
4. **Access requests.**
5. **Meeting attendees and scheduling.** `meeting-invite`, `meeting-reminder`,
   `meeting-minutes`.
6. **Push when closed.** Web Push, FCM.

## Decisions (2026-09-28, Joep)

- Recipients whose private drive is on another server or only on a device:
  skip for now.
- A meeting starting notifies everyone with access to the drive.
- Changes to things you follow: every change, batched rather than sent one by
  one.

## Open questions

- The push gateway for self-hosted Android: pick one (UnifiedPush is the
  FOSS-friendly default), or leave Android push to atomic.place for now?
