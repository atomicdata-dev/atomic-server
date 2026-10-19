# atomic.place Flutter — Agent Context

## Sync & onboarding — read first

The Dart in `lib/atomic/` is a client of the same system the data-browser
talks to, and the same person uses both. Before changing anything about
signing in, servers, pairing or sync, read
[`../planning/sync-onboarding-ux.md`](../planning/sync-onboarding-ux.md): it
holds the shared vocabulary, the rules of what can actually reach what (rights
decide, on every transport — not whose device it is), every account/device path, and
the map of which file here twins which file in `browser/data-browser`.

Change a sync screen here → change its twin there, and update that doc.

## What This Is

A cross-platform infinite drawing canvas app, migrated from a Kotlin/Android + Jetpack Compose app at `../atomiccanvas`. The Flutter version targets Android, iOS, and Web from a single codebase.

## Why Flutter

The original Kotlin app is feature-complete (CRDT-backed canvas, undo/redo with branches, lasso selection, transforms, gallery with folders). The migration was chosen because iOS and web support are needed. Flutter's `CustomPainter` maps well to Compose's `Canvas` API, and `flutter_rust_bridge` enables reusing the Rust/Loro CRDT code across platforms.

## Architecture Decisions

### Storage: atomic-server (not local files)

The Kotlin app stores Loro snapshots as local files. The Flutter app uses **atomic-server** as the backend via REST API, with `atomic_lib` (Rust crate) wrapped through `flutter_rust_bridge`. Authentication uses Ed25519 keypairs (agents). This is a deliberate shift toward cloud-synced storage.

### Rust Integration: flutter_rust_bridge v2

- **Mobile (Android/iOS)**: FFI via `flutter_rust_bridge` — works with `dart:ffi`
- **Web**: WASM compilation — `flutter_rust_bridge` handles this, but `dart:ffi` is unavailable on web, so the bridge generates WASM bindings automatically
- Rust source lives in `/rust/src/`. Keep it thin: logic that another host
  (Tauri, a native shell, the CLI) could use goes in `atomic_lib::host`
  (`lib/src/host/`: lists, chats, conversations, recents, embed dispatcher) with
  its tests; the bridge binds it to the global store (`rust/src/host.rs`).
- `atomic_lib` is referenced as a local path dependency: `../../../atomicdata-dev/atomic-server/lib`

### Loro CRDT: Not Yet Integrated in Flutter

The Kotlin app has full Loro CRDT integration (via JNI). The Flutter app currently stores strokes as plain JSON strings to atomic-server. Loro integration is the biggest remaining gap — it needs to be added as a Rust dependency and exposed through `flutter_rust_bridge` for proper offline-first CRDT sync and persistent history.

### Canvas Coordinate System

`screenPos = canvasPos * scale + offset` — same convention as the Kotlin app. The `CanvasPainter` applies `translate(offset) + scale(scale)` before drawing. All stroke points are stored in canvas space.

### Gesture Model

- **Stylus** → draw
- **Single finger** → draw (pen tool) or pan (select tool)
- **Two fingers** → pinch zoom + pan (always, regardless of tool)
- The Kotlin app also supports 2-finger tap = undo, 3-finger tap = redo — not yet ported

### History System

Uses sealed `HistoryAction` classes (`StrokeAdded`, `StrokesDeleted`, `StrokesReplaced`). Undo/redo works by reversing/replaying actions. The Kotlin app also has `DiscardedBranch` — when you undo and then draw, the discarded future is preserved as a branch you can restore. This is partially ported (model exists) but not fully wired up.

## File Structure

```
lib/
├── main.dart                    # App entry, MaterialApp, theme
├── theme.dart                   # AppColors, Material 3 theme
├── rust_init.dart               # Platform-conditional Rust init
├── atomic/
│   ├── atomic_client.dart       # FFI wrapper (conditional import)
│   └── session.dart             # Auth persistence (SharedPreferences)
├── canvas/
│   ├── infinite_canvas.dart     # Main canvas widget (651 lines)
│   ├── canvas_painter.dart      # CustomPainter for strokes
│   ├── fan_helpers.dart         # Color/width fan picker math
│   └── thumbnail.dart           # Thumbnail generation
├── gallery/
│   ├── gallery_screen.dart      # Canvas list + folder management
│   └── canvas_store.dart        # CRUD + state for canvases
├── models/
│   ├── stroke_data.dart         # StrokeData + HistoryAction
│   └── canvas_entry.dart        # Canvas metadata model
├── screens/
│   └── login_screen.dart        # Agent auth screen
├── widgets/
│   ├── toolbar.dart             # Left-side tool palette
│   ├── bottom_toolbar.dart      # Bottom button bar
│   ├── fan_overlay.dart         # Color/width fan CustomPainter
│   └── history_scrubber.dart    # Undo timeline slider
└── src/rust/                    # Auto-generated flutter_rust_bridge
```

## What's Done (~35%)

- Core canvas with drawing, pan, zoom
- Stroke rendering with bezier smoothing (CustomPainter)
- Pen tool with color fan (8 hues x 4 shades) and 7 width options
- In-memory undo/redo with action replay
- Gallery with folder organization (local only)
- atomic-server integration (agents, drives, canvas CRUD)
- flutter_rust_bridge setup with atomic_lib bindings
- Login/auth screen
- Theme system (Material 3)

## What's Missing (~65%)

### Critical (must-have for parity)
1. **Loro CRDT integration** — add loro crate to Rust, expose through bridge. Needed for offline-first sync, persistent history, and conflict resolution
2. **Selection + Transform tools** — lasso selection, bounding box handles, scale/rotate/translate strokes
3. **Eraser tool** — stroke deletion by tap/drag
4. **Image import** — background images on canvas
5. **Auto-save** — periodic + on-background save
6. **Thumbnail generation** — PNG thumbnails for gallery (use `dart:ui` Picture recorder)

### Important (UX parity)
7. **Multi-finger gestures** — 2-finger tap undo, 3-finger tap redo
8. **Stylus hover preview** — show cursor/brush preview on hover
9. **Zoom scrubber** — fine-grained zoom control widget
10. **Fit content** — zoom to fit all strokes with padding
11. **Discarded branches UI** — show/restore abandoned history branches
12. **History persistence** — save/restore undo history across sessions

### Nice-to-have
13. **Folder sync** to atomic-server (currently local-only)
14. **Pressure sensitivity** — vary stroke width by pressure
15. **Tests** — port GeometryTest and CanvasUiTest

## Reference: Kotlin Source

The original app lives at `../atomiccanvas`. Key files:
- `app/src/main/java/com/ontola/atomiccanvas/MainActivity.kt` — 2,558 lines, contains everything
- `app/src/main/java/com/ontola/atomiccanvas/LoroManager.kt` — 87 lines, Loro JNI wrapper
- `app/src/main/rust/src/lib.rs` — 197 lines, JNI bindings for Loro

## Dev Environment

- Flutter 3.44+ (via mise, see `flutter/.mise.toml`)
- Rust toolchain for flutter_rust_bridge (needs wasm32 target for web)
- atomic-server as backend (local or remote)
- Run: `mise exec -- flutter run -d chrome` (web) or `flutter run` (mobile)

## Gotchas

- `flutter_rust_bridge` auto-generates files in `lib/src/rust/` — don't edit those manually
- `atomic_lib` path dependency means you need `atomicdata-dev` checked out alongside this repo
- The Kotlin app uses `android.graphics.Color.HSVToColor` for the color fan — Flutter uses `HSVColor.toColor()` instead
- On web, `dart:ffi` is unavailable — the bridge handles this but any new Rust bindings must be tested on web too
- The Kotlin app is a single 2,558-line file. The Flutter version is already better structured — keep it that way
