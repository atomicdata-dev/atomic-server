# Flutter app: tablet and wide-screen layout

> **Status:** reworked after Joep's feedback (2026-10-20): the rail is gone,
> the phone's bar spans the window, the list pane folds away, section
> headings got search / new / all buttons. Seen on the Android tablet
> emulator; not yet on the Samsung SM-X810 or the Xiaomi Pad. Code:
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
| >= 600 | `split` | The same bottom bar, the window's width; above it a list pane (home or search) and a detail pane with the pages. |

- **Bar**: Home, Search, +, Profile, Settings, and on a tablet the
  resource's ⋮ after Settings (on the phone ⋮ takes Settings' place). On a
  wide window the buttons are a centred group (at most 560 dp; a 48 dp slot
  is kept for ⋮ so nothing moves when a resource opens). Home and Search
  show what the list pane holds, and bring a folded list pane back; Home on
  the home closes the detail page. The + list opens above the + as on the
  phone.
- **+ opens on the way down** (`HoldFan.opensOnDown`, raw pointer
  listener): the list is there in the frame the finger lands; moving more
  than 8 dp drags through the rows, letting go picks (or, off the rows,
  closes); lifting without moving leaves it open for a tap. Other hold
  menus (Search's drives, headings, the home's +) wait 150 ms.
- **List pane** (`_SplitPanes`): two fifths of the room, 320–400 dp, or the
  width it was dragged to (280–520, the pages keep 280). Folds away: a tab
  on the divider (24x48, a 48x64 target, chevron), a drag on the divider
  (resizes; dragged far left it folds), or Home/Search in the bar (unfold).
  Folding animates in 140 ms; the list keeps its width while it slides (no
  relayout per frame) and stays built (scroll, folds). The fold and the
  dragged width are per device in SharedPreferences (`listCollapsedKey`,
  `listWidthKey`) and survive resize and rotation. Folded with nothing
  open, the detail pane offers "Show list".
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

- [x] Rail removed (`AppNavRail`, `HoldFanLayout.side`), bar full width.
- [x] Collapsible, resizable list pane, remembered per device.
- [x] Section buttons, heading wash, All in the detail pane.
- [x] + opens on pointer down, drag-select without waiting.
- [x] Bar follows a layout change (seen: it kept Settings next to ⋮ after
  a tablet→phone resize).
- [x] Tests: `tablet_layout_test.dart` (phone, 800x1280, 1280x800, 851x393,
  640 and 599 wide, fold/unfold timing, fold through rotation and phone
  size, prefs, drag resize/fold, All in the detail pane, section search /
  +, headings at font 1.3 and 360 dp, the wash), `bottom_bar_test.dart`,
  `hold_fan_test.dart` (opensOnDown, rounded label).

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
