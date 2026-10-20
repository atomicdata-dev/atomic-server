# Flutter app: tablet and wide-screen layout

> **Status:** reworked after Joep's feedback (2026-10-20): the rail is gone,
> the bar is at the foot of the sidebar (list pane), the sidebar folds away,
> section headings got search / new / all buttons. Fixed after the Samsung
> SM-X810 showed only the bar's buttons in the sidebar (see "Samsung fix"). Code:
> `packages/atomic_chat/lib/src/app_shell.dart` (`ShellLayout`,
> `_SplitPanes`, `_PaneHandle`), `app_bottom_bar.dart` (`AppBottomBar`,
> `ShellActions`), `chats_screen.dart` (`_Section`), `search_screen.dart`
> (`SearchKind`), `atomic_flutter/lib/src/hold_fan.dart`; tests in
> `packages/atomic_chat/test/tablet_layout_test.dart`.

## Design

The shell picks a layout from the window's width (`ShellLayout.forWidth`,
logical pixels):

| Width | Layout | What it is |
| --- | --- | --- |
| < 600 | `bar` | The phone: pages in one navigator above the bottom bar. |
| >= 600 | `split` | A list pane (home or search) with the bottom bar at its foot, and a detail pane with the pages, full height. |

- **Bar under the sidebar only** (2026-10-20, Joep: a full-width bar wastes
  room in landscape): in `split` the bar is at the foot of the list pane,
  exactly its width (`_SplitPanes` positions it; one keyed instance, so it
  is not rebuilt when it moves). The list pane's minimum is 304 dp (six 48
  dp slots incl. the resource's ⋮, plus padding). The profile button shows
  the name next to the avatar when the bar is >= 400 dp wide (the default
  sidebar at 1000+ dp windows), else the avatar only. The buttons start at
  the left of the bar, the resource's ⋮ sits at its right end. The bar is
  flush at the bottom, its colour under the system navigation inset. The
  detail pane runs to the bottom of the window. **Folded**: the bar slides
  away with the sidebar (no floating bar); the pages have the whole window
  and the tab at the left edge (or a swipe from it) brings both back. The
  home's header (wordmark) has a Close sidebar button. Keyboard: the bar is
  covered by it as on the phone; the list pane sees the keyboard minus the
  bar's height, the detail pane the whole keyboard.
- **Reopening in one gesture**: a tap on the tab, or a drag that starts at
  the left edge (a 24 dp strip, `_PaneHandle.edgeStrip`, starting beyond
  `MediaQuery.systemGestureInsets.left` so Android's back swipe keeps the
  very edge; it is a Flutter widget above the pages' web view) and follows
  the finger: the list width tracks it, then settles (<= 140 ms) open past
  a third of the width or on a fling > 300 dp/s, else back folded. A fling
  left on the divider strip folds it. While the list moves, the pages are
  laid out at the width they will have and clipped (no per-frame web view
  resize, no blank strip); only dragging the divider to resize resizes them.
- **Bar**: Home, Search, +, Profile, Settings, and on a tablet the
  resource's ⋮ at the bar's right end (on the phone ⋮ takes Settings'
  place; a 48 dp slot is kept for it so nothing moves when a resource
  opens). Home and Search show what the list pane holds; Home on the home
  closes the detail page. The + list opens above the + as on the
  phone.
- **+ opens on the way down** (`HoldFan.opensOnDown`, raw pointer
  listener): the list is there in the frame the finger lands; moving more
  than 8 dp drags through the rows, letting go picks (or, off the rows,
  closes); lifting without moving leaves it open for a tap. Other hold
  menus (Search's drives, headings, the home's +) wait 150 ms.
- **List pane** (`_SplitPanes`): two fifths of the room, 320–400 dp, or the
  width it was dragged to (280–520, the pages keep 280). Folds away: a tab
  on the divider (24x48, a 48x64 target, chevron), a drag on the divider
  (resizes; dragged far left it folds), or the header's Close sidebar.
  Folding animates in 140 ms; the list keeps its width while it slides (no
  relayout per frame) and stays built (scroll, folds). The dragged width is
  per device in SharedPreferences (`listWidthKey`); the fold survives
  resize and rotation but not a restart (every start shows the sidebar).
  Folded with nothing open, the detail pane offers "Show list".
- **Detail pane**: the shell's one navigator. A row opens in place of what
  was shown, except over a section's full list (`ShellPage.isList`), where
  it opens over it and back returns to the list.
- **Section headings** (home): the title (tap folds, hold arranges) with a
  rounded 8 dp wash that hugs the title and chevron (`HoldFan.borderRadius`;
  it was a round ink in the middle of the whole row), the chevron turns.
  At the right edge icon buttons (24 dp icons, 48 dp targets, tooltips):
  Search (`SearchKind`: Drives → drives, AI chats → chats, Messages →
  chat rooms/conversations, others everything; none on Notifications),
  + (Drives → `/app/new-drive`, AI chats → new chat, Messages → web form
  for a ChatRoom, Recents → the New list; none on Activity, Notifications,
  Favorites), All (whole section in the detail pane on a tablet, a page on
  the phone; shown once the section has anything).
- **Search kinds**: a chip next to the field names the kind, with a way
  back to everything; before typing it lists all of that kind (drives,
  chats, conversations); a drive hit opens the drive rather than scoping.
- **Readable width**, **insets**, **state across resize** as before: the
  navigator and the home are moved, not rebuilt; a search moves between a
  page (bar) and the list pane with text, drive and kind.

## Done

- [x] Rail removed (`AppNavRail`, `HoldFanLayout.side`), bar full width
  (later: only under the list pane, see above).
- [x] Profile button: avatar (picture, emoji, initial) and name from
  `AssistantApi.ownIdentity`, cached in `ShellController.identity`,
  refreshed on resume and when the profile page is left or entered.
- [x] Collapsible, resizable list pane (the width remembered per device).
- [x] Section buttons, heading wash, All in the detail pane.
- [x] + opens on pointer down, drag-select without waiting.
- [x] Bar follows a layout change (seen: it kept Settings next to ⋮ after
  a tablet→phone resize).
- [x] Tests: `tablet_layout_test.dart` (phone, 800x1280, 1280x800, 851x393,
  640 and 599 wide, fold/unfold timing, fold through rotation and phone
  size, prefs, drag resize/fold, All in the detail pane, section search /
  +, headings at font 1.3 and 360 dp, the wash), `bottom_bar_test.dart`,
  `hold_fan_test.dart` (opensOnDown, rounded label).

## Samsung fix (2026-10-20)

Joep on the SM-X810 (1752x2800 px at 340 dpi = 824x1318 dp portrait, not
1030 wide): the sidebar held only the six buttons, Home did nothing, and
folded there was a floating bar card over a black strip.

- Root cause 1: the profile button (once the identity loaded, i.e. signed
  in) was `ConstrainedBox(minHeight: 48) > Center` without height factor,
  so it took all the height it was offered. On the phone the bar is in a
  Column (unbounded height: harmless); next to the pages the bar was in an
  `OverflowBox` with the pane's height, so the bar became the whole
  sidebar and the list (padded by the bar's height) got none. The tablet
  tests had no identity, so they never saw it. Home "did nothing" because
  the home it showed was zero high.
- Root cause 2: folded, `_DetailInset` ended the pages above the floating
  compact bar, and nothing painted the strip under it: the window's black.
- The fold was remembered per device, so a fold made once stayed for every
  start.
- The avatar's fallback circle is drawn in the main colour's tint, which
  read as "Profile is the current page"; it is neutral now unless it is.
- [x] Tests at 1752x2800 @ 340 dpi with a 48 dp gesture inset and a
  signed-in person (`tablet_layout_test.dart`, "the Samsung Galaxy Tab").

## Seen on the tablet emulator (Tablet_A35, 2560x1600 @ 320 dpi = 1280x800 dp)

- 2026-10-20 (rework): list pane 400 dp, bar across the bottom, section
  buttons at the right edge; All → Recents in the detail pane with back;
  fold (tab) → the page takes the width, tab at the left edge; Home
  unfolds; + tap leaves the list open above it, a 200 ms swipe from + to
  "AI chat" picks it; a document open, portrait and back with the list
  folded keeps both; font scale 1.3 fits (tablet and a 1080x2400 phone
  size). Mid-fold the web view lags the pane's width by a frame or two
  (blank strip at the right while it animates). Dark mode not seen: the
  app's own theme setting stayed light.

Earlier (rail version):

Pixel_Tablet_API36 does not start from this session (no HVF for its API 36
image); Tablet_A35 has the same screen.

- Onboarding full width, centred column. Home in the list pane, "Open
  something from the list" in the detail pane.
- Drive and a new document (rail New → hold → Document → name) open in the
  detail pane, rows marked; the home re-reads (Recents, Activity update).
  The ⋮ sits in the page's header and the web menu opens under it.
- Typing in the document, then rotating to portrait and back: same page,
  text, cursor and keyboard. The edit was kept after reopening.
- Search in the list pane with the keyboard (field above it, page next to
  it untouched); hits open in the detail pane.
- Settings, Sync (profile), AI chat (no account state), chat room from the
  drive's Chat room button (native screen pushed within the pane), sending
  with the keyboard, rotating with text in the composer.
- Dark and light theme; font scale 1.3 (rail labels fit).
- Display resized to a phone (`wm size 1080x2400`, density 420) with a
  document open: the phone layout with the bar and its ⋮, same document.

## Still open / to check on the real tablets (Samsung SM-X810, Xiaomi Pad)

- The fold animation with a web page open (does the page keep up, or show
  a strip while it resizes?), the tab's place and size under a thumb, and
  dragging the divider (and that it does not fight the system back swipe
  when folded: the tab is at the left edge).
- + drag straight from the bar; that a scroll or back swipe starting near
  + is not taken by it.
- The bar's centred group on 1280+ dp: the empty ⋮ slot makes the group sit
  24 dp left of centre when nothing is open.
- Section + targets: `/app/new-drive` and the ChatRoom form
  (`/app/new?classSubject=…ChatRoom`) in the embedded web view.
- Dark mode of the tab, the headings' wash and the section buttons.
- Real density: at 1800x2880 the Pad is about 800x1280 dp (split in both
  orientations; 600 dp in a split-screen half); check the list/detail
  proportions there.
- Freeform / split-screen windows and drag-resizing (the emulator only had
  `wm size`); the widget tests cover the transitions.
- Stylus and keyboard/mouse: no hover states or keyboard shortcuts yet.
- The warm web view is attached and laid out under the detail pane before
  it is taken (`WarmPageSlot`): check on the Pad that a taken page shows at
  once and that rotating with only the spare loaded keeps it.
- A resource reached by navigating inside the page is not marked in the list
  (the mark follows what was opened from the list).
- Once seen: the search pane showed a hit still marked after Settings took
  the detail pane's place; not reproduced (the widget test for exactly that
  passes).
- The new-document sheet is a centred bottom sheet capped at Material's
  640 dp; a dialog might suit a tablet better.
