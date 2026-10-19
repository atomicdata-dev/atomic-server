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
      onOpenGallery: null, // the host's other part; no button when null
    ),
  ),
);
```

## What is in it

| Part | Files |
| --- | --- |
| The seam and its types | `AssistantApi`, `models.dart` (`ChatSummary`, `ChatMessage`, `ConversationMessage`, `ConversationRow`, `SearchHit`, `DriveInfo`, `RecentResource`, `ActivityEntry`, `visibleDrives`, `driveKey`, `AssistantJson`) |
| Shell | `AppShell`, `ShellController`, `ShellScope`, `AppBottomBar`, `SlideBackRoute`, `CoveredInsetsFreeze` |
| Screens | `ChatsScreen` (home sections, `timeAgo`, `groupChatsByAge`), `ChatScreen`, `ConversationScreen`, `SearchScreen` |
| Resources | `openResourceView` and the native view registry, `ResourceView`, `EmbedServer`, `ResourceWebView`, `ResourceRow`, `iconForClass` |
| AI and voice | `HostedAi`, `voice.dart`, `hosted_voice.dart` (the `voice_*` SharedPreferences keys) |
| Small widgets | `FadingText`, `AtomicPlaceMark` |

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
