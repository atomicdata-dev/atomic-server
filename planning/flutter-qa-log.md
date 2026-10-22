# Flutter app: open QA findings

Click-through QA on the emulator (2026-10-19/20). Fixed findings are in
PR #2310's history; only what is still open is kept here.

## Needs a decision

- AI chat without an account has no in-app path to link one: Sync only
  offers "Link your account" next to a managed server (self-hosted nodes must
  not push accounts).
- Meetings are hidden from the drive page (web rule); on a phone that hides
  them except via Home and Search.
- A new person on "Sign in with atomic.place" gets no hint how to make an
  account.

## Not fixed

- Web dialogs and forms with the keyboard up do not scroll the focused field
  fully into view (New Table's Name, New page's "Build with AI").
- Web copy written for a desktop: "Click to focus document…", "drop files on
  this page".
- A new table selects its title for editing after the dialog already asked
  for the name. A table's `#` column takes a quarter of a phone's width.
- The home shows its default section order for a moment before the saved one.
- The first start after choosing a theme can flip from dark to light once.
- Sideways, the bottom and top bars take ~40% of the height; the web page
  leaves a grey strip at the cutout side.
- Recently opened rows in search show `class · drive`, the home `drive ·
  class · time`.

## To check on a real device

- HoldFan's long press and drag-to-pick under a thumb; haptics.
- Light/Dark/Auto across the app, and the status/navigation bar icon colours.
- Landscape with the keyboard: chat composers and search field.
- Whether a long web page still reads as scrollable without a scrollbar.
