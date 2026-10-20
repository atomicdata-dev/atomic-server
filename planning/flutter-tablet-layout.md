# Flutter app: tablet and wide-screen layout

> **Status:** built and seen on the Android tablet emulator (2026-10-20).
> Not yet seen on the real Xiaomi Pad (1800x2880). Code:
> `packages/atomic_chat/lib/src/app_shell.dart` (`ShellLayout`, `AppShell`),
> `app_bottom_bar.dart` (`AppNavRail`), tests in
> `packages/atomic_chat/test/tablet_layout_test.dart`.

## Design

The shell picks one of three layouts from the window's width
(`ShellLayout.forWidth`, logical pixels):

| Width | Layout | What it is |
| --- | --- | --- |
| < 600 | `bar` | The phone, unchanged: pages in one navigator above the bottom bar. |
| 600–720 | `rail` | A navigation rail at the left instead of the bar; pages beside it, as on the phone. |
| >= 720 | `split` | Rail, a list pane (the home or a search) and a detail pane with the pages. |

So a tablet in portrait (800 dp) and landscape (1280 dp), and a phone
sideways (~850 dp), all get the split layout. 720 rather than 840: an 800 dp
portrait tablet then still has a 430 dp detail pane (wider than a phone)
next to a 290 dp list, and rotating a tablet keeps one structure.

- **Rail** (`AppNavRail`, 80 dp, `barSurface`): Home, Search, New, Profile,
  Settings, each with its name under it, the current one in the main colour.
  Search and New keep their hold menus; on the rail they open to the right
  of the button (`HoldFanLayout.side` in `atomic_flutter`). In the split
  layout Home and Search show what the list pane holds, the others what the
  detail pane shows (two can be current: the home list next to Settings).
  Home on the home closes the detail pane's page.
- **List pane** (40% of the room, 280–380 dp): the home, or a search
  (`ShellController.list`). The home stays built behind a search, so its
  scroll and folds survive. "Show all" lists the rest in place there
  instead of a page of its own. Back with nothing open in the detail pane
  takes a search back to the home.
- **Detail pane**: the shell's one navigator (the same `navigatorKey`). Its
  first page shows "Open something from the list". A row opens with
  `ShellController.openDetail` / `openFromList`: on a phone a push (as
  before), in the split layout it takes the place of what was shown
  (`pushAndRemoveUntil` to the first page), and its row is marked
  (`ShellController.selected`, `ResourceRow.subject`). Pages opened inside a
  page (a chat room from a meeting, a linked resource) push within the pane,
  and back goes back within it. Rail pages (New, Profile, Settings) also
  replace the detail page.
- **Resource menu** (⋮): on the phone the bar's last button; with a rail it
  sits at the detail pane's top right, inside the page's 36 px header row
  (`_DetailMore`), and the menu opens under it.
- **Insets**: under the rail and panes a strip of the system's bottom inset
  in the bar's colour takes the bar's place, so `_PagesInset` (keyboard
  minus bar) works unchanged; the panes drop the side insets they do not
  touch. The home in the list pane does not see the keyboard of the detail
  pane's pages.
- **Readable width**: `ReadableWidth` (720 dp, centred) around chats,
  conversations, chat rooms, search (all through `ListAndField`), the web
  settings / new-resource pages and Sync. Login and onboarding are outside
  the shell and stay full screen.
- **State across resize and rotation**: the navigator (global key) and the
  home (`_homeKey`) are moved, not rebuilt, when the layout changes: the open
  resource keeps its web view and what was typed, the home its scroll. A
  search moves between a page (bar, rail) and the list pane (split) with its
  text and drive (`ShellController.search`, `SearchScreen.initialQuery`).

## Done

- [x] Layouts, rail, list and detail panes, selection, menu, insets.
- [x] `HoldFanLayout.side` for the rail.
- [x] Search in the list pane takes the focus even when the web page next
  to it had it (`autofocus` alone did not).
- [x] New (+) always gives a new chat: a chat stops being "new" as soon as
  something is sent (with a slow host the + did nothing from inside a chat
  with messages); on an empty new chat the + focuses its field; on a voice
  chat it opens a typed one (`ShellController.onReselect`).
- [x] Tests: `tablet_layout_test.dart` (phone 393x851, tablet 800x1280 and
  1280x800, phone sideways 851x393, 640 wide rail-only, resizes between
  them keeping the same State objects and typed text, search moving, back,
  rail at font 1.3 with 48 dp targets, the 720 cap), the rail fans in
  `bottom_bar_test.dart`, `hold_fan_test.dart`. Phone tests run at phone
  size by default (`test/flutter_test_config.dart`; the test default of
  800x600 is a tablet now).

## Seen on the tablet emulator (Tablet_A35, 2560x1600 @ 320 dpi = 1280x800 dp)

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

## Still open / to check on the Xiaomi Pad

- Real density: at 1800x2880 the Pad is about 800x1280 dp (split in both
  orientations); check the list/detail proportions there.
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
