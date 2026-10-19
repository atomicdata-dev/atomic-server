# Flutter embed: a real host contract

> **Status:** plan, started 2026-10-19. Follows `planning/flutter-resource-webview.md`
> (the embed itself works: documents, folders, tables render from the Rust store;
> edits are being made to persist).

The embedded renderer (`browser/data-browser/src/embed/`) runs the web app's
`ResourcePage` inside an Android/iOS web view, with the Rust `atomic_lib` store
as the only database. It works, but a review on 2026-10-19 found that it holds
together with small hacks in the web code and one wrong assumption in the store.
This plan replaces the hacks with a contract the web app knows and tests, and
makes the embed cheaper to run.

## What is wrong today

1. **"Online" means "has a server".** The Store only saves local edits when it
   believes it is connected (`scheduleOutboxDrain`, `Resource.save` offline path).
   The embed has no server by design, so edits stayed in the page and were lost
   when the web view was destroyed. Flipping `serverConnected` is not an option: it
   changes read paths. *Fixed:* a commit transport on the Store
   (`store.canCommit`), plus a flush before the page leaves (step 1).
2. **Hacks instead of a contract.** `hideGlobalChrome` is switched on by an
   `isEmbedded()` flag; `env(safe-area-inset-*)` is rewritten by patching
   `CSSStyleSheet.insertRule` and a `MutationObserver`; the action routes are
   mounted by reading `route.options.component` of the app's own routes; the
   comments panel is rendered by a special case in `Navigation.tsx`. Each of
   those breaks silently when the web app's CSS or routing changes.
3. **Cost per page.** A new Android web view per resource (memory, first paint),
   navigation is a page load, and a 13 MB bundle that must be rebuilt by hand
   after every web change.
4. **Everything is web.** Chat and conversations are native, but tables, lists and
   the long tail of views all pay the web view's cost.

## Steps

Each step ships on its own and has a test that fails without it.

- [x] **0. Host logic lives in atomic_lib.** What the Flutter bridge crate did
  that is not Flutter-specific moved to `atomic_lib::host` (`lib/src/host/`,
  native builds with the `db` feature), so the Tauri desktop app, native
  iOS/Android shells and the CLI can bind the same code. Moved: the embed call
  dispatcher with its signing policy (`host::embed::EmbedHost`), the recents /
  activity / chat index with its persistence and event listener
  (`host::recents::RecentsIndex`), list rows (`host::rows`: `row_resource`,
  `class_name_of`, `with_emoji`, `name_of`, `DriveCache`), the home lists and
  search (`host::lists`), AI chats read and written (`host::chats`), encrypted
  conversations listed, read and sent, with the agent-name and opened-message
  caches (`host::conversations`), and resource text for an AI
  (`host::context`). Two seams stay with the host: `LocalWritePusher` (the
  bridge's `push_local_write`: WS drain, live peers, peer nudge) and
  `AgentNameFetcher` (the bridge asks the connected server). The bridge
  (`flutter/rust/src/host.rs`) keeps the statics, frb attributes, `ws_sync`,
  Iroh peers and canvas CRUD; its public functions kept their signatures, so
  the Dart bindings were not regenerated. Tests moved with the code (each on
  its own in-memory store, `host::test_support::Device`); the bridge keeps
  one end-to-end test per function.
- [x] **0b. The Dart host parts in a package.** The assistant screens moved
  from the app to `packages/atomic_chat` (depends on `atomic_flutter`, never on
  the app or the bridge), so another Flutter app can use them: the shell and
  bottom bar, home, AI chat, conversations, search, `ResourceView` /
  `EmbedServer` / `ResourceWebView`, the native view registry
  (`registerNativeView`), voice and `HostedAi`. `AssistantApi` is now an
  interface; the app implements it over the bridge
  (`flutter/lib/assistant/atomic_assistant_api.dart`), and the JSON of
  `atomic_lib::host` is read by `AssistantJson` in the package. App-owned
  pages are parameters (`AppShell.profile`, `ChatsScreen.onOpenGallery`). The
  embed bundle stays an app asset (`scripts/build_embed.sh`), served from
  `EmbedServer.assetRoot`. `AppColors` moved to `atomic_flutter`. Tests moved
  with the code (`packages/atomic_chat/test`, on fakes); CI runs both packages
  (`atomic-flutter.yml`).
- [x] **0c. More from the bottom bar.** A reusable `HoldFan` (tap = default,
  touch-and-hold-drag = a fan of choices, after the canvas fans;
  `packages/atomic_flutter`) on New (AI chat, AI voice, Document, Other) and
  Search (all drives, the four drives used last, More…). New document is
  native: `NewDocumentSheet` → `AssistantApi.createResource` →
  `create_resource_of_class` (bridge) → `atomic_lib::host::create` (a
  `DocumentV2` needs only class, name and parent, as the web's basic "New"
  handler makes it; the editor writes the Loro content on first edit), then
  the web renderer. Other opens the embed's `/app/new?parentSubject=<drive>`.
  AI voice is `ChatScreen(voiceMode: true)`, a turn-by-turn loop (listen →
  send → speak → listen) on the existing speech engines; `/ai/live` stays out.
  The bar shows the current page and never opens one twice (`ShellPage`
  route names, `ShellController.open`). Tests: `hold_fan_test.dart`,
  `bottom_bar_test.dart`, `host::create`, the bridge's
  `a_document_created_here_…`. Not yet seen on a phone (haptics, fan
  geometry under a real thumb, TTS completion before listening again).
- [x] **1. Commit transport and flush.** Store option `commitTransport`,
  `canCommit` for write-side checks, `atomicEmbed.flush()` and the Dart handshake
  before leaving a page. A keystroke now travels: loro-prosemirror commits the
  doc → the resource's Loro subscriber marks it dirty (`canCommit`) → the
  outbox drain signs one commit (`sign` on the host) → `commitTransport` →
  `applyCommit` (Rust adds the `@id`, applies with `LocalCache`, queues it, and
  pushes it on in the background). Leaving: back / swipe back / a page pushed
  over / app paused call `flush`, which runs the debounced saves
  (`store.flushScheduledSaves`), drains and waits for `pendingDirtyCount === 0`
  (3 s cap); Dart waits for the `flushed` message (2 s cap). `signBytes` now
  signs genesis certificates of the device's agent, so "New resource" can mint
  a DID. Tests: `commit-transport.test.ts`, `resource_view_test.dart`, the
  `embed.rs` document-edit round trip (`lib/src/host/embed.rs`, and through the
  bridge in `flutter/rust/src/embed.rs`). Not yet seen on a phone.
- [ ] **2. One host module.** Move the embed's special cases into
  `browser/data-browser/src/embed/host.ts` with a documented `EmbedHost` surface:
  `{ channel, insets, panels, routes }`. The web app sees one typed object:
  safe-area insets come from the host as CSS variables (`--embed-inset-*`, used
  by the layout components that today read `env()`), panels are an explicit allow
  list, action routes are registered by the embed through an exported
  `embedRoutes` instead of reading another route's options. Delete the
  `insertRule` patch. Unit tests for the host surface; a Playwright smoke in
  mobile width.
- [x] **3. Bundle budget in CI.** `flutter/scripts/check_embed_size.sh` fails when
  the entry plus first-use chunks exceed a gzip budget (start: today's 553 kB +
  297 kB) or the total exceeds 16 MB; run in the Flutter workflow (`embed-size` job in `atomic-flutter.yml`). Report the sizes
  in the job summary. Measured: 45 first-use chunks, 926 kB gzip (budget 1 MB), 13.6 MB total.
- [~] **4. One warm web view.** Built, not yet measured on a phone.
  `WarmResourceWebView` (`packages/atomic_chat/lib/src/warm_resource_web_view.dart`)
  is made by `AppShell.initState` (so after login and the host's open_db) and
  holds ONE hidden web view with `embed.html` loaded and booted. The page posts
  `{method:'ready'}` on `AtomicFlutter` once up (`embed.tsx`; fallback: poll
  `typeof window.atomicEmbed`). `ResourceView` takes it (`ShellController.warm`),
  swaps the channel handler to itself, runs `atomicEmbed.open(subject)` (replaces
  the blank first history entry so back leaves the resource; falls back to
  `show`), and the pool starts the next spare after 600 ms (so the open is not
  competing with a 13 MB load). Not ready, failed, `path` pages (settings) or no
  pool: the cold path, as before. A taken (or cold) page is released 3 s after the
  view closes. The spare is dropped after 5 min in the background or on memory
  pressure, and warmed again on resume. Logs: `[warm] taken ready=...`,
  `[warm] open N ms first content`, `[warm] cold open N ms first content`.
  Still open: measure on the Xiaomi (first content < 250 ms, memory with the
  spare), check that a detached Android web view boots (timers, WASM) and lays
  out right when attached, and rebuild the bundle (`build_embed.sh`) so `open`
  and `ready` exist (without them: `show` and polling).
- [ ] **5. Native views for the hot types.** Registry entries, one at a time,
  each with an escape hatch to the web renderer: AI chat (done), conversations
  (in progress), then table rows list, folder list, file preview. Rule: native
  only where the list or composer is used every day and the web version's cost is
  felt.
- [ ] **6. Features that need chrome.** Decide per feature: comments (done as an
  overlay), AI sidebar and "Add to chat" (open the native chat with the resource
  as context), follow-session (leave out), share (web dialog in the embed).

## Settings in the embed

The app's bottom bar opens the web settings page (`?path=/app/settings`). It
persists in the page's own `localStorage` (same keys as the web app: `darkMode`,
`mainColor`, `atomic.locale`, `hideTemplates`; the host keeps one stable origin so
they survive app starts). The page used to show every web section. Which of them
make sense on a phone (allow-list: `src/embed/settings.ts`, used by
`routes/AppSettings.tsx`; outside the embed everything is shown as before):

| Section / option | Status in the embed | Action |
| --- | --- | --- |
| Appearance > Theme (Auto/Dark/Light) | Worked in principle (theme is derived in JS by `useDarkMode`), but "Auto" depended on `prefers-color-scheme`, which an Android web view only follows with force-dark configured, and a listener closed over its first-render setting, so the OS flipping scheme could override an explicit choice | Fixed: listener reads the live setting; `atomicEmbed.setColorScheme('light'/'dark')` lets the host report the app's mode and "Auto" follows it, else the media query; `color-scheme` is set on `<html>` so scrollbars and controls match. Persists as `darkMode` |
| Appearance > Main color | Works (pure theme input, `mainColor`) | Kept |
| Appearance > Language | Works (`atomic.locale`, catalogs are bundled) | Kept |
| Appearance > Hide templates on new resource page | Works (the embed mounts the New route) | Kept |
| Appearance > NavBar position | Not relevant: the embed has no navbar, the app has its own bottom bar | Hidden |
| Appearance > Colorful mode | Not relevant: only tints the sidebar/navbar (`ChromeTheme`), absent here | Hidden |
| Appearance > Panels (Messages, Favorites, Shared with me, Ontologies, AI Chats) | Not relevant: no sidebar; the app's native screens own chats and navigation | Hidden |
| Accessibility > page transition animations | Broken/unsupported: experimental, known to misbehave outside desktop Chromium (including Android) | Hidden |
| Accessibility > keyboard drag & drop in sidebar | Not relevant: no sidebar, no keyboard | Hidden (whole section) |
| Notifications | Broken: uses the `Notification` API (desktop/Tauri plugin); the Android web view has none, so it only ever said "unsupported". The native app owns notifications. No in-page subset exists (the toggle is the only control) | Hidden |
| Virtual drive | Not relevant: desktop (Tauri) only; already off on mobile | Hidden |
| AI (providers, keys, Ollama, MCP, voice, models) | Not relevant/broken: the AI chat is native with its own settings and voice; Ollama/MCP/local discovery are desktop concepts | Hidden |
| Integration (proxy, plugin catalog) | Not relevant: desktop/server plugin catalog | Hidden |

The page's Theme choice is the app's too: the page reports its saved and every
new choice (`reportTheme` in `src/embed/hostActions.ts`, a `theme` call with
`auto`/`dark`/`light`), and the app saves it and switches its own screens
(`AppThemeMode` in `packages/atomic_chat`, read by `MaterialApp` in
`flutter/lib/main.dart`). Before, picking Light left the app's bars and home
dark around a light page. The host reports its resulting scheme back with
`atomicEmbed.setColorScheme` (`ResourceView._tellColorScheme`), so "Auto"
follows the system through the app. In the embed the page has no "Settings"
heading or search field (the app's top bar has the title, one section needs no
search), and Appearance starts open.

Tests: `src/embed/settings.test.tsx` (allow-list, and the page rendered
embedded vs not), `src/helpers/useDarkMode.test.tsx` (persistence under the web
key, auto vs explicit, host scheme, the choice reported to the app),
`hostActions.test.ts`, `resource_view_test.dart` (the `theme` call). Not
verified without a device: the transparent web view background in dark mode.

## Meetings in the embed

"Open chat" on a meeting page called `openMeetingPanel`, which only selects the
follow-session side panel; the embed renders no side panels except comments, so
nothing appeared. Decision:

- **Open chat**: the page asks the app to show the chat in its own screen
  (`openNative('chatroom', subject, title)`, `src/embed/hostActions.ts`, a call
  on the AtomicFlutter channel answered `true` when the app opened it). The
  app's `ResourceView` handles it (`openNative` in `resource_view.dart`): when
  `nativeViews` has the kind it pushes `ChatRoomScreen` over the page and
  answers true. A meeting is a chat room of its own (the log sits under the
  meeting), so the same screen shows both. A link to a `ChatRoom` inside the
  page does the same (`useNativeChatRoom`), and the page goes back to where the
  link was. `ChatRoom` is also in the native views registry, so opening one from
  a list or search skips the web page.
- **Fallback**: `src/embed/MeetingChatOverlay.tsx` shows the meeting's chat
  (the web app's `ChatRoomView`: messages and composer, writing through the
  commit transport like every other write) full screen, with a close button,
  when the app answers false or does not know the call (desktop mock, an older
  app). The call and the presence list of the web panel are left out.
- **Back**: the overlay registers in `src/embed/overlayBack.ts`;
  `atomicEmbed.back()` closes the topmost overlay first and returns true.
- **Start meeting**: hidden in the embed (`showMeetingStart` in
  `src/embed/settings.ts`). It starts a presence session over the server
  connection (the embed has none) and a WebRTC call needing microphone and
  camera, which the host does not grant the web view. "End meeting" only shows
  for a meeting started on the page, so it follows.

The native chat: `lib/src/host/chat_rooms.rs` reads the room's `ChatLog` entries
plus old `Message` resources (an old message that has its entry is left out) as
`text` or `event` lines (entry kind `FollowEvent`; a "Viewing [title](subject)"
trail line carries the viewed resource) and writes an entry like the web's
`appendToChatLog` (`t`, `a`, `c`, `r`, same page rule), so web clients show it.
Any other entry kind shows as plain text (`t`, else `description`, else AI-style
text parts). Bridge: `read_chat_room`, `send_chat_room_message`. Screen:
`ChatRoomScreen` in `packages/atomic_chat` (bubbles with author name and
initial, grey one-line event rows that open the viewed resource, composer),
re-read every few seconds like the conversation screen.

Tests: `src/embed/MeetingChatOverlay.test.tsx`, `hostActions.test.ts`, the host
tests in `chat_rooms.rs`, `chat_room_screen_test.dart`, `resource_view_test.dart`.
Not verified without a device: the screens on a phone (keyboard resize, live
messages from others, which need the host to push `changed`; the native screen
polls instead), and the web bundle with these page changes (the thread session
rebuilds it).

## No server in the page (fresh account, 2026-10-19)

A fresh account's drive opened as its raw subject and "Empty". The host read
the drive fine; the page then "refreshed it from the server" (the drive
page's plugin lookup, `useDriveClass`), which signed an HTTP request through
the host. The host signs only commits, and the refusal became the drive's
error. The auth cookie on `setAgent` and the plugin list asked for the same
signature. Fixed with a Store option `noServer` (`browser/lib`): every read
comes from the client database (the host), nothing goes over HTTP, no auth
cookie. The embed's store is made in `src/embed/embedStore.ts`, which also
registers the create actions and delete dialogs `App.tsx` registers (without
them the drive's Document / Folder buttons opened the bare property form).
Tests: `no-server.test.ts`, `src/embed/embedStore.test.ts`,
`host::embed` `a_fresh_identitys_drive_opens_with_its_name`.

Found on the way: the app's sign-in with the saved secret on every start
replaced the agent's stored resource with a nameless one ("Someone created",
"You"); `load_agent_from_secret` now keeps what the store holds. The home
reloads when a page of the bottom bar closes.

Still open: a resource opened by navigating inside the page (a folder's
child, the drive's quick-create) is not noted as opened, so it is missing
from Recents; the page's Data view (`DataRoute.fetchAs`) still signs an HTTP
request (refused, harmless).

## Not planned

- Running the web app's own router or sidebar in the embed.
- A second store or a WebSocket inside the page.
- Raw signing for the page: only commits of the device's own agent (`sign`) and
  genesis certificates naming it (`signBytes`) are signed
  (`lib/src/host/embed.rs`).
