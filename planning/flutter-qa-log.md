# Flutter app QA log

Click-through QA of the Flutter app on the Android emulator (1080x2400,
arm64, debug build), as a new user would, with a local-only identity (no
atomic.place account). One entry per finding: what was tried, what was seen,
and whether it was fixed (commit) or not.

## 2026-10-19 (overnight round)

### Home

- Tap a section heading: folds and unfolds. Works.
- Hold a heading: the menu (Move up / Move down / Hide / Show) only showed
  while the finger stayed down; a plain long press (press, let go) flashed it
  and dropped it, so the usual menu gesture did nothing. **Fixed**
  (`HoldFan: a plain long press keeps the menu open for a tap`): letting go
  where the hold started keeps the menu up; a tap on a pill picks it, a tap
  elsewhere closes it. The menu also opened over the middle of the row
  instead of over the finger: fixed in the same commit.
- The heading's menu opened under the status bar (the top pill overlapped
  the clock). **Fixed** (`HoldFan: keep the menu out of the status bar`).
- Move up on Activity, force-stop, start: the order persisted. Works.
- An empty section ("No chats yet") was a centred block with 32 px around it,
  taller than a section with a row. **Fixed** (`Home: an empty section is one
  quiet line`).
- Recents rows: `drive · class · time`; Activity rows: `who did what · time`.
  Correct. A meeting showed a document icon. **Fixed** (`Rows: a meeting shows
  a camera`).
- A meeting with chat messages showed under "AI chats". **Fixed** (`host
  recents: a meeting with messages is not an AI chat`).
- Scroll with ~8 items: no jumping seen (down and back up).

### Drive page and creating things (web embed)

- A grey desktop scrollbar ran along the right edge of every web page,
  always visible, taking 9 px. **Fixed** (`Embed: no desktop scrollbar`).
- Folder, Table (dialog), Meeting, Document: all create and open. After
  creation the title is selected with the keyboard up, also for a table that
  was just named in the dialog (redundant; web behaviour, not changed).
- New Table dialog with the keyboard up: the Name field is cut off at the
  bottom of the dialog's scroll area (the focused field is not scrolled fully
  into view). Not fixed (web dialog).
- A table on a phone: the `#` column takes about a quarter of the width.
  Not fixed (web table).
- A meeting is not listed on the drive page (Activity or Resources): the web
  app hides meetings from drive lists on purpose (`useVisibleDriveChildren`,
  the desktop reaches them from the meeting UI). On the phone it is reachable
  from Home (Recents, Activity) and Search. Not changed; worth a decision.
- The editor's placeholder says "Click to focus document…" on a touch
  screen. Not fixed (translated web string).

### + menu

- AI chat / AI voice without an account: an "Add context?" picker for a chat
  that cannot be had, and one small line at the bottom ("No AI is set up on
  this device."). **Fixed** (`AI chat without an account says why`): the page
  says AI chat needs an atomic.place account, no picker, no composer. Not
  done: a way to sign in from there. A local identity has no path to link an
  account in the app (Sync only offers "Link your account" next to a managed
  server, by design for self-hosted nodes); that needs a product decision.
- Other → the web New page: "Build with AI" did nothing when tapped (no AI
  provider in the web view). **Fixed** (`Embed: the web app's AI features are
  off in the app's web view`).
- Document → native sheet, name, keyboard ✓ → opens the document. Works.

### Meeting and chat room

- Meeting → "Open chat" opens the native chat screen (the embed → host
  `openNative` handoff works). Sent messages with the button and the
  keyboard's send key; bubbles, time, back to the meeting page. Works.
- Chat room from the drive page opens straight in the native screen, named
  the web's default "ChatRoom" with no way to change it. **Fixed** (`Chat
  room: rename it from its top bar`, `Chat room rename: the old name starts
  selected`). The drive page kept the old name after the rename:
  `atomicEmbed.changed()` answered from memory. **Fixed** (`Embed: a resource
  changed in the app's own screen shows on the page`).
- Event lines ("Viewing …") not seen: they need another participant
  following a session; untested here.

### Search

- A short query ("re") across all drives listed only built-in properties
  (requested-subject, previous-release, …), never the person's "Recipes".
  **Fixed** (`host search: the person's own things before schema`).
- Recently opened rows show `class · drive`, the home shows `drive · class ·
  time`: a small inconsistency, not changed.
- A query without hits left the page blank; searching inside a drive listed
  the drive itself as the best hit. **Fixed** (`Search: say when nothing is
  found; a drive is no hit inside itself`).
- Picking a drive result scopes the search (chip `In: <drive>`, ✕ clears it).
  Back closes the keyboard, then the page. Works.

### Settings (embedded web page)

- The title showed twice (app top bar and the page's h1) above a search field
  for the only section, Appearance, which started folded. **Fixed** (`Embed
  settings: no second title and no search for one section`).
- Theme → Light turned only the web page light; the app's bars, home and chat
  stayed dark around it. **Fixed** (`The theme chosen in Settings is the whole
  app's`, `Warm page: the theme it reports while booting reaches the app`).
  Light, Dark and Auto now switch the whole app and survive a restart.

### Sync / profile

- Identity, workspace switcher, This device, Devices; no account, no credits
  row. The agent ID under the name copied on tap but gave no hint. **Fixed**
  (`Sync: the agent ID shows it can be copied`).
- Every start and every return to the app toasted "No peer on network: Found
  1 NodeID(s) but all are ours (<64 hex>)" on a device without other devices.
  **Fixed** (`Sync: a drive on one device is not a sync error`).
- The workspace sheet opens above the bottom bar, which is not dimmed (the
  shell keeps the bar). Not changed.

### Start-up

- Every home section (also Notifications, Favorites, Messages, which hide when
  empty) showed a heading and a spinner, a screen of spinners, then the empty
  ones vanished. **Fixed** (`Home: sections hidden when empty stay hidden
  while they load`). The default section order still shows for a moment
  before the saved one (prefs are read async); not changed.

### Landscape and font size

- Home sideways: the rows kept out of the camera cutout, the headings did not.
  **Fixed** (`Home sideways: headings keep out of the camera cutout`).
- Search, chat room, AI chat and conversation sideways with the keyboard up:
  "BOTTOM OVERFLOWED BY 6.1 PIXELS" under the field. **Fixed** (`Search
  sideways: no overflow…`, `Chats sideways: no overflow…`).
- Sideways the bottom bar and top bar take about 40% of the height; the web
  page leaves a grey strip at the cutout side. Not changed.
- Font scale 1.3: home, AI chat state, settings fine.

### Sign-in screen (after `pm clear`)

- Welcome: Get Started, I have a secret, Sign in with atomic.place.
- "I have a secret": field obscured, reveal works, Paste with an empty
  clipboard says "Nothing to paste". A wrong secret showed "Invalid key. Not
  valid Base64. Invalid last symbol 116, offset 9." in small red on dark red.
  **Fixed** (`Sign in: a secret that is not one says so in words`).
- System back on "I have a secret" / "Create your identity" / "Sync your
  drive" left the app. **Fixed** (`Sign-in screen: system back returns to the
  welcome step`).
- "Sign in with atomic.place": the code dialog (code, waiting, open in
  browser, Cancel); Cancel returns cleanly to the welcome screen. Not
  completed. A new person without an account gets no hint there how to make
  one. Not changed.
- New identity: "Continue to Atomic" and "recover your account" (it is an
  identity, not an atomic.place account). **Fixed** (`New identity: say what
  the secret is for, and plain Continue`).
- The visible read-only "Account: atomic.place" field on "I have a secret"
  (there for password managers) reads as if an account were needed. Not
  changed: the create step hides it with Offstage, whether autofill still
  pairs there on Android was not checked.

## Not fixed, worth a look

- AI chat without an account has no in-app path to link one: Sync only
  offers "Link your account" next to a managed server (self-hosted nodes must
  not push accounts). Needs a decision.
- Meetings are hidden from the drive page (web rule); on a phone that hides
  them except via Home and Search.
- Web dialogs and forms with the keyboard up do not scroll the focused field
  fully into view (New Table's Name, New page's "Build with AI").
- Web copy written for a desktop: "Click to focus document…", "drop files on
  this page".
- A new table selects its title for editing after the dialog already asked
  for the name.
- The home shows its default section order for a moment before the saved
  one.
- The first start after choosing a theme in a session where the app did not
  know it yet flips from dark to light once the warm page boots (once only:
  it is saved).

- 2026-10-20 (performance round): after the app was killed (force-stop,
  `install -r`, an ANR), its store would not open three times: a redb
  assertion (`raw_file_len >= header.layout().len()`) panics in `open_db`
  and the app stays black. **Fixed** (second store handle after a
  same-process relaunch); see "Store lost after a kill" in
  `flutter-performance.md`.

## On a real device

- HoldFan: a long press that stays as a menu, and the drag-to-pick, under a
  real thumb; haptics.
- Theme: Light/Dark/Auto across the app, and the status/navigation bar icon
  colours in light mode.
- Landscape with the keyboard: chat composers and search field (now field
  only below 120 dp).
- The scrollbar-free web pages: still clear that a long page scrolls?
