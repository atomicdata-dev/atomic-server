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
  `embed.rs` document-edit round trip. Not yet seen on a phone.
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
- [ ] **4. One warm web view.** A shell-level `EmbedPool` keeps a loaded web view
  (page ready, Loro WASM compiled) and shows a resource with `show(subject)`
  instead of a page load; a second one is created lazily so the page below stays
  visible during the slide-back. Measure first-content time and memory before and
  after on the Xiaomi test phone (budget: first content < 250 ms for a stored
  resource).
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

Tests: `src/embed/settings.test.tsx` (allow-list, and the page rendered
embedded vs not), `src/helpers/useDarkMode.test.tsx` (persistence under the web
key, auto vs explicit, host scheme). Not verified without a device: that the
Android web view reports `prefers-color-scheme` as the app's mode (the host
should call `atomicEmbed.setColorScheme` on start and on theme change; that Dart
call is not wired yet), and the transparent web view background in dark mode.

## Not planned

- Running the web app's own router or sidebar in the embed.
- A second store or a WebSocket inside the page.
- Raw signing for the page: only commits of the device's own agent (`sign`) and
  genesis certificates naming it (`signBytes`) are signed
  (`flutter/rust/src/embed.rs`).
