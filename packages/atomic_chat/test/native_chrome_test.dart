import 'dart:convert';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

const _parent = 'https://atomicdata.dev/properties/parent';
const _name = 'https://atomicdata.dev/properties/name';
const _isA = 'https://atomicdata.dev/properties/isA';

/// A store with Home > Projects > the screen's own resource.
class _TreeApi extends FakeApi {
  final String? url;
  final renamed = <(String, String)>[];

  _TreeApi({this.url});

  static const _tree = <String, Map<String, Object>>{
    'did:ad:home': {_name: 'Home'},
    'did:ad:projects': {
      _name: 'Projects',
      _parent: 'did:ad:home',
      _isA: [chatRoomClass],
    },
    'did:ad:res': {_name: 'Standup', _parent: 'did:ad:projects'},
  };

  @override
  Future<String> embedCall(String method, String argsJson) async {
    final subject = (jsonDecode(argsJson) as List).first as String;
    return jsonEncode(_tree[subject]);
  }

  @override
  String webUrl(String subject) => url ?? super.webUrl(subject);

  @override
  Future<List<ChatRoomMessage>> chatRoomMessages(String s) async => [];

  @override
  Future<void> renameResource(String subject, String name) async =>
      renamed.add((subject, name));
}

/// Opens [screen] on top of the shell's home, as a resource is opened.
Future<void> _push(WidgetTester tester, _TreeApi api, Widget screen) async {
  SharedPreferences.setMockInitialValues({});
  await tester.pumpWidget(app(AppShell(
      api: api,
      drive: 'did:ad:home',
      warmPool: (_) => null,
      home: const Scaffold(body: Text('home')))));
  final shell = tester.widget<ShellScope>(find.byType(ShellScope)).controller;
  shell.navigatorKey.currentState!
      .push(MaterialPageRoute<void>(builder: (_) => screen));
  await tester.pumpAndSettle();
}

/// Taps the bar's "more" button.
Future<void> openMoreMenu(WidgetTester tester) async {
  await tester.tap(find.byTooltip('More'));
  await tester.pumpAndSettle();
}

void main() {
  final screens = <String, Widget Function(_TreeApi)>{
    'chat room': (api) => ChatRoomScreen(
        api: api,
        drive: 'did:ad:home',
        subject: 'did:ad:res',
        title: 'Standup'),
    'conversation': (api) => ConversationScreen(
        api: api,
        drive: 'did:ad:home',
        subject: 'did:ad:res',
        title: 'Standup'),
    'AI chat': (api) => ChatScreen(
        api: api,
        drive: 'did:ad:home',
        subject: 'did:ad:res',
        title: 'Standup'),
  };

  for (final MapEntry(key: name, value: build) in screens.entries) {
    group('the $name', () {
      testWidgets('shows the breadcrumbs of the web page', (tester) async {
        final api = _TreeApi();
        await _push(tester, api, build(api));
        final bar = find.byKey(const Key('breadcrumbs'));
        expect(find.descendant(of: bar, matching: find.text('Home')),
            findsOneWidget);
        expect(find.descendant(of: bar, matching: find.text('Projects')),
            findsOneWidget);
        // The title bar names the resource itself.
        expect(find.descendant(of: bar, matching: find.text('Standup')),
            findsNothing);
      });

      testWidgets('has the more menu, with the link when there is a server',
          (tester) async {
        final api = _TreeApi(url: 'https://x.test/show?subject=did:ad:res');
        await _push(tester, api, build(api));
        await openMoreMenu(tester);
        // A conversation is named by its members: nothing to rename.
        expect(find.text('Rename'),
            name == 'conversation' ? findsNothing : findsOneWidget);
        expect(find.text('Copy link'), findsOneWidget);
        expect(find.text('Open in browser'), findsOneWidget);
      });
    });
  }

  testWidgets('a crumb opens that resource', (tester) async {
    final api = _TreeApi();
    await _push(tester, api, screens['chat room']!(api));
    await tester.tap(find.text('Projects'));
    await tester.pumpAndSettle();
    expect(api.opened, ['did:ad:projects']);
    expect(find.byType(ChatRoomScreen, skipOffstage: false), findsNWidgets(2));
  });

  testWidgets('without a server the menu has no link to give', (tester) async {
    final api = _TreeApi();
    await _push(tester, api, screens['chat room']!(api));
    await openMoreMenu(tester);
    expect(find.text('Rename'), findsOneWidget);
    expect(find.text('Copy link'), findsNothing);
    expect(find.text('Open in browser'), findsNothing);
  });

  testWidgets('the room is renamed from the more menu', (tester) async {
    final api = _TreeApi();
    await _push(tester, api, screens['chat room']!(api));
    await openMoreMenu(tester);
    await tester.tap(find.text('Rename'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('chat-room-name')), ' Family ');
    await tester.tap(find.text('Save'));
    await tester.pumpAndSettle();
    expect(api.renamed, [('did:ad:res', 'Family')]);
    expect(find.text('Family'), findsWidgets);
  });

  testWidgets('copies the link', (tester) async {
    String? copied;
    tester.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, (call) async {
      if (call.method == 'Clipboard.setData') {
        copied = (call.arguments as Map)['text'] as String;
      }
      return null;
    });
    addTearDown(() => tester.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, null));
    final api = _TreeApi(url: 'https://x.test/show?subject=did:ad:res');
    await _push(tester, api, screens['chat room']!(api));
    await openMoreMenu(tester);
    await tester.tap(find.text('Copy link'));
    await tester.pumpAndSettle();
    expect(copied, 'https://x.test/show?subject=did:ad:res');
  });

  testWidgets('a new chat is not in the drive yet: no crumbs, no menu',
      (tester) async {
    final api = _TreeApi();
    await _push(tester, api, ChatScreen(api: api, drive: 'did:ad:home'));
    expect(find.byKey(const Key('breadcrumbs')), findsNothing);
    expect(find.byTooltip('More'), findsNothing);
  });
}
