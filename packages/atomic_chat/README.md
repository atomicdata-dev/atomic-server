# atomic_chat

The assistant screens of the atomic.place Flutter app, as a package another
Flutter app can use: the home (drives, recents, activity, AI chats, favorites,
messages), AI chat with the linked account's hosted AI and voice,
conversations (DMs and group chats), search, and resources drawn by the web
app's embedded renderer. It depends on `atomic_flutter` (account client,
`AppColors` theme tokens) and on Flutter plugins (web view, speech, TTS,
recording), never on a native bridge or on the app.

```dart
import 'package:atomic_chat/atomic_chat.dart';

MaterialApp(
  theme: ThemeData(extensions: const [AppColors.light]),
  home: AppShell(
    api: const MyAssistantApi(),
    drive: activeDrive,
    profile: (_) => const MyProfilePage(), // pops `true` on sign-out
    home: ChatsScreen(
      api: const MyAssistantApi(),
      drive: activeDrive,
      onSignOut: signedOut,
    ),
  ),
);
```

## What is in it

| Part | Files |
| --- | --- |
| The seam and its types | `AssistantApi`, `models.dart` (`ChatSummary`, `ChatMessage`, `ConversationMessage`, `ConversationRow`, `SearchHit`, `DriveInfo`, `RecentResource`, `ActivityEntry`, `visibleDrives`, `driveKey`, `AssistantJson`) |
| Shell | `AppShell`, `ShellController` (`ShellPage` kinds, `open`/`openPage`), `ShellScope`, `AppBottomBar`, `SlideBackRoute`, `CoveredInsetsFreeze` |
| Screens | `ChatsScreen` (home sections, `timeAgo`, `groupChatsByAge`), `ChatScreen` (also `voiceMode`), `ConversationScreen`, `SearchScreen` (also `scopeDrive`), `NewDocumentSheet` |
| Resources | `openResourceView` and the native view registry, `ResourceView`, `EmbedServer`, `ResourceWebView`, `ResourceRow`, `iconForClass` |
| AI and voice | `HostedAi`, `voice.dart`, `hosted_voice.dart` (the `voice_*` SharedPreferences keys) |
| Small widgets | `FadingText`, `AtomicPlaceMark`, `HoldFan` (from `atomic_flutter`, re-exported) |

## The bottom bar

Home, Search, New, Profile and Settings (or the page's More menu). The
button of the page on top is the current one: dimmed with a dot under it, and
a tap does nothing. Pages the bar opens carry a route name (`ShellPage`:
`home`, `search` / `search:<drive>`, `new-chat`, `voice-chat`,
`new-resource`, `profile`, `settings`); `ShellController.open(kind, …)`
pushes one only when none is on top, pops back to it when it is further down,
and ignores a second push within 300 ms (a double tap). A host page opened
from the bar goes through it as well (`AppShell.profile` is opened as
`profile`).

New lists its kinds on a tap; Search has more choices on touch and hold:

- **New**: tap = a list (hold = the same list, drag to a row): *AI chat* (always
  a fresh one; on an empty new chat its field gets the cursor), *AI voice* (`ChatScreen`
  with `voiceMode`: listens at once with the chosen speech engine, sends
  after a pause, reads the answer aloud and listens again until Stop, leaving,
  the app going to the background or an error), *Document* (the native
  `NewDocumentSheet`: name, drive, Create through `AssistantApi.createResource`;
  the drive is remembered as `new_resource_drive`), *Other…* (the web app's
  `/app/new` page in that drive).
- **Search**: tap = every drive. Hold: *All drives*, the four drives used
  last, *More…* for the rest; a drive opens `SearchScreen(scopeDrive: …)`,
  which says `In: <drive>` with an x back to every drive.

## HoldFan

A button with a default action on tap and more on touch-and-hold, or (with
`tapOpensMenu`, as on New) a list on tap and the same list to drag through on
hold. It lives in `atomic_flutter` (no dependency on this package) and is
re-exported here. Choices are always one vertical list (`HoldFanLayout.list`
above the button, `.side` to the right of a rail button); there is no fan.

```dart
HoldFan<String>(
  tooltip: 'New',
  tapOpensMenu: true,                   // a tap lists the items too; without it onTap runs
  items: const [
    HoldFanItem('AI chat', 'chat', icon: Icons.chat_bubble_outline),
    HoldFanItem('AI voice', 'voice', icon: Icons.mic_none),
    HoldFanItem('Document', 'doc', icon: Icons.description_outlined),
  ],
  onSelected: (value) => open(value),
  child: const Icon(Icons.add),         // what the button shows; HoldFan is the tap target
)
```

A tap (with `tapOpensMenu`) opens the list at once as a rounded card of rows
(icon and label, 48 dp) in the root overlay, over a slightly dimmed page:
tap a row to pick it; a tap elsewhere, or back (`HoldFan.dismissOpenMenu`,
called by the shell), closes it. Hold about 250 ms (a haptic tick) and the
same list opens; slide onto a row (it lights up, a tick per change) and let go
to pick it. Letting go elsewhere or a cancelled touch picks nothing; letting
go where the hold began keeps the list open to tap. Without `tapOpensMenu`
(Search, the Home headings) a hold shows the items as pills in the same kind
of column. Screen readers get a long-press action (`menuLabel`, "More
options") that lists the same items in a plain sheet. `onOpen` runs as the
list opens (to refresh the items for next time); `selected` marks it as the
current page.

## Wiring a host

**`AssistantApi`.** Every read and write of the screens goes through it; the
package has no other way to the store. Implement it over your client and pass
it to `AppShell`, `ChatsScreen` (and anything you open yourself). If your store
answers with the JSON of `atomic_lib::host` (lists, chats, conversations,
search), `AssistantJson` reads it. `hostedAi()` returns the linked account's
AI: read the saved session from your own storage and call
`HostedAi.forSession(session)`; return null when no account is linked.
`embedCall` answers the embedded page's calls (see `ResourceView`). The
atomic.place app's implementation is `flutter/lib/assistant/atomic_assistant_api.dart`
(over the flutter_rust_bridge bindings, which stay in the app).

**Host pages.** The user's page (agent, sync, account) belongs to the host:
pass it as `AppShell.profile` (or `ChatsScreen.profile`). It pops with `true`
when the person signed out, and the home then calls `onSignOut`. Without a
profile page the Profile button is off.

**The embed asset bundle.** `ResourceView` shows resources the native views do
not cover with the web app's renderer (`browser/data-browser/src/embed/`),
served by `EmbedServer` on the loopback address from the host's assets. The
package does not ship the bundle: the host builds it and declares it as
assets. The atomic.place app runs `flutter/scripts/build_embed.sh` into
`flutter/assets/embed/` and declares `assets/embed/` and
`assets/embed/assets/` in its pubspec. That is `EmbedServer.assetRoot`'s
default; another location (or another `AssetBundle`, `EmbedServer.bundle`) is
set before the first resource opens.

**Native views.** `nativeViews` maps a class shortname to the native view for
it; AI chats (`ai-chat`) and conversations (`conversation`) are registered by
default, everything else opens in the web renderer. A host adds or removes one
with `registerNativeView(className, builder)` (a class URL works too; null
removes it).

**Theme.** The screens read `context.appColors`: register `AppColors.light` /
`AppColors.dark` (from `atomic_flutter`, re-exported here) in the theme.

**Platform setup.** The host app grants what the plugins need: the
microphone and speech permissions for voice (`RECORD_AUDIO`,
`NSMicrophoneUsageDescription`, `NSSpeechRecognitionUsageDescription`), and on
Android cleartext to `127.0.0.1` for the embed's loopback server (the app's
`res/xml/network_security_config.xml`).

Run `flutter analyze` and `flutter test` in this directory. Tests use fakes
(`test/unimplemented_api.dart`, `FakeApi` in `test/assistant_screens_test.dart`).
