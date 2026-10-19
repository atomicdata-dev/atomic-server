# Flutter: showing a resource with the web app's renderer

> **Status:** Design, for review (2026-10-19). Nothing of the embed is built.
> Written after Joep's two constraints: the mobile store is `atomic_lib` in
> Rust only (no WASM/OPFS store in the webview), and only the resource page is
> rendered, not the web app's chrome.

## Why this exists

The Flutter app lists chats and recently opened resources natively. Opening a
resource (a document, a table, a canvas, a folder) means the web app's renderer:
rewriting every view in Flutter is not an option. Today a resource opens at
`{server}/app/show?subject=…` in a `WebView`. That page is the whole web app.
It starts its own store (WASM `ClientDb` in OPFS, the agent from IndexedDB),
finds no agent, and shows "Enter your agent secret to unlock this drive on this
device" instead of the content. Fixing the sign-in would make it worse: a second
copy of the data in OPFS, a second WebSocket to the server, a second identity
store, plus the sidebar, the navbar and a dozen watchers
(`CloudVaultWatcher`, `PairingLinkHandler`, `DeviceLockWatcher`, …) around the
page, in a webview that must be fast.

## Constraints

1. One store on the device: `atomic_lib` in the Flutter bridge. The webview
   holds no database of its own and does not talk to the network.
2. The agent's secret stays native. Commits are signed in Rust.
3. Render `ResourcePage` only (`browser/data-browser/src/views/ResourcePage.tsx`):
   no sidebar, navbar, search overlay, pairing, vault or lock components.
4. Works offline for anything already on the device.
5. Fast: opening a resource that is stored locally shows content in well under
   a second, and swiping between pages never waits for a page load.
6. Reuse, not fork: the same React views and `@tomic/lib` as the web app.

## What the web app already gives us

- `Store.setClientDb(db)` takes any object with the `ClientDbWorker` surface
  (`browser/lib/src/client-db.ts`); `NodeClientDb`
  (`client-db.node.ts`, 379 lines) is a second implementation that proves the
  surface can be filled by something other than the OPFS worker. The `Store`
  itself only calls a small part of it: `getResourceWithSnapshot(s)`,
  `getVersionVectorsForDrive/Subjects`, `getDriveSubjects`, `query`,
  `getBlob`, `flush`, `applyPeerCommit`, and the readiness getters. Views also
  reach `search`, `putResource(s)`, `applyCommit`, `removeResource` and the
  outbox methods through the store's save path.
- `Agent` takes a `CryptoProvider` (`sign`, `signBytes`, `getPublicKey`;
  `browser/lib/src/CryptoProvider.ts`). A provider that asks the host to sign
  keeps the key out of JavaScript. (`signsDeterministically` must be true: the
  private drive's DID is derived from a signature.)
- `Store({ connect: false })` keeps it off the network.
- The Tauri build already proves the shape: `initClientDb` is skipped there and
  the store reads from the node in the same process.

## Options

**A. The web app from a server, signed in inside the webview (today).**
Needs the secret in the webview, a second store and a second sync connection,
loads the whole app. No offline. Rejected: breaks constraints 1, 2, 3, 4.

**B. An HTTP node inside the app, the unmodified web app on `localhost`.**
Embed the server crate's handlers over the same `Db`. The web app and its store
work unchanged (like Tauri). But: a listening port on the device (any app can
connect; needs a per-launch token), the actix stack and search in the Android
binary, and still the whole app UI to strip. Possible later; much more
platform surface than the problem needs.

**C. A bundled embed entry, with a JS bridge to Rust. Recommended.**
The web app gets a second entry (`embed.html` / `embed.tsx`) that mounts only
`StoreContext` + the settings and theme providers + `ResourcePage`. Its store is
`new Store({ connect: false })` with `setClientDb(new NativeClientDb(channel))`
and an agent built on `NativeCryptoProvider(channel)`. The bundle ships inside
the Flutter app as assets. Rust serves every read and signs every write.

## Design of C

```
Flutter (Dart)                         WebView (warm, local assets)
 ResourceView page  ──show(subject)──▶  embed.tsx
        ▲                                 ├ Store(connect:false)
        │ JS channel "atomic"             ├ NativeClientDb  ─┐ request {id, method, args}
        └──────────── reply {id, result} ◀┤ NativeCrypto…  ─┘ (async, batched)
 Rust atomic_lib: get_resource, snapshots, version vectors, query, search,
 blobs, apply commit (signs with the agent), outbox → sync as today
```

**Channel.** One request/reply protocol over `JavaScriptChannel` (webview →
Dart) and `runJavaScript` (Dart → webview). Requests carry an id; replies
resolve a promise. Binary (Loro snapshots, blobs) goes as base64 in v1; if it
shows up in a profile, blobs move to a `flutter-asset://`-style local URL
handler instead of the channel. Batches: the store already asks for many
subjects at once (`getResourcesWithSnapshots`), so a page load is a handful of
round trips, not hundreds.

**Writes.** A save signs through `NativeCryptoProvider` (a channel call into
Rust, Ed25519), hands the signed commit to `NativeClientDb.applyCommit`, which
applies it in `atomic_lib` and queues it on the outbox. From there it is the
same path as every other local edit (`push_local_write`: live peers, server,
paired device). The webview never opens a WebSocket.

**Live updates.** Rust already emits `DbEvent`s. Dart forwards the changed
subjects to the webview (`changed([subjects])`); `NativeClientDb` refetches
them and the store updates its resources. This replaces the server WebSocket.

**Navigation.** Native owns the stack. A link inside a resource calls back
(`open(subject)`) and Flutter pushes the next resource page with the slide-back
route, so the swipe back and the animation are the same as everywhere else.
The webview gets `show(subject)` and renders it, with no router and no history.
Open decision (below): one warm webview shared by the stack, or two.

**What is rendered.** `ResourcePage`, which is the web app's one registry of
views: it picks the view by the resource's class (`selectComponent`: document,
table, canvas, folder, file, chat, article, ontology, …) and the per-drive
pages that cannot be a fixed case (plugins, apps, websites, via
`useCustomViews`). The embed gets every view with it, nothing is chosen or
ported per view; the heavy ones are already lazy chunks (`TablePage`,
`DashboardPage`, website, plugins), so they cost nothing until opened. Mounted
under the providers it really needs. Anything in the tree that reaches for the router, the sidebar or a
dialog host gets a small adapter or a no-op, found by running it, not guessed.
Theme and locale come from the host (`prefers-color-scheme` follows the app).

**Performance.**
- One webview created at app start (or on the home screen's first idle frame)
  and kept warm; the embed bundle is loaded once from local assets.
- Navigating is a `show(subject)` message, not a page load.
- The first resource's data is pushed along with `show`, saving the first
  round trip.
- Loro's WASM (documents, history) is code, not storage: it loads lazily with
  the document chunk.
- Budgets to measure on the phone: `show` → first content for a stored
  resource, page memory, bundle size (gzip), channel calls per page.

**Security.** The webview loads only bundled assets (no remote navigation, no
`file://` access beyond the asset folder, JavaScript channels exposed only to
that origin). Resource content is rendered as the web app renders it, so
markdown/HTML sanitising stays the web app's job; because the secret is not in
the webview, a rendering bug cannot read it.

## What changes where

| Where | Change |
| --- | --- |
| `browser/lib` | `NativeClientDb`, `NativeCryptoProvider` (small, behind the existing interfaces); no change to `Store` unless a gap shows up |
| `browser/data-browser` | `embed` entry (Vite multi-page), providers + `ResourcePage`, adapters; build output copied to Flutter assets |
| `flutter/rust` | the channel's calls as plain async functions over what exists (get, snapshots, version vectors, query, search, blobs, apply commit, sign) |
| `flutter/lib` | `ResourceView` page replacing `ResourceWebView`: warm webview, channel, `show`/`changed`/`open` |

## Plan, in steps that each prove something

1. **Embed entry in a desktop browser, reading from a stub.** `embed.tsx` with
   `NativeClientDb` backed by a mock channel (fixtures). Proves `ResourcePage`
   renders without the chrome and lists what it still pulls in. Measure the
   bundle.
2. **Rust side of the channel + a bare webview in Flutter.** Read-only: show a
   document and a folder from the real store on the phone. Measure first
   content and memory.
3. **Writes and signing.** Edit a document, a table cell; the commit is signed
   in Rust and reaches the server and a paired device.
4. **Live updates and navigation.** `changed`, `open`, stack and slide-back,
   the warm webview (or two).
5. **Hardening.** One pass per view family (document, table, canvas, folder,
   files, chat, plugin/app pages): offline, large documents, files and images (blobs), error
   states, accessibility, dark mode, and memory on the tablet.

## Open decisions (Joep)

1. Resource-to-resource navigation: native stack with a *second warm webview*
   so the previous page stays visible under the slide-back (recommended, about
   the cost of one more webview), or one webview and a re-render on back.
2. Is a feature flag (`?embed`) in the normal web build acceptable, or should
   the embed be its own build target so the web app's size and tests are
   untouched? Recommended: own Vite entry, same package.
3. Files and images: through the channel as base64 at first, or straight away a
   local asset URL scheme.

## Risks

- `ResourcePage` pulling in more of the app than expected through contexts (a
  sidebar-dependent hook, a router link). Mitigated by step 1 running it
  before any Flutter work.
- Channel latency under heavy views (a table of thousands of rows). Mitigated
  by batching and by the store's existing paging; measured in step 2.
- Per-drive plugin and app pages run code from the drive; they need their own
  check (what they load, whether they assume a network). They are in the
  registry, so they appear; whether they work is step 5.
- The embed bundle growing with every web feature. Mitigated by the lazy
  chunks `ResourcePage` already has, and a size budget in CI.
