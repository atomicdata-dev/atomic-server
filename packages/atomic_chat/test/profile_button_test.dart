import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

class _Api extends FakeApi {
  ProfileIdentity? who;
  _Api(this.who);

  @override
  Future<ProfileIdentity?> ownIdentity() async => who;
}

void _size(WidgetTester tester, Size size) {
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = size;
  addTearDown(tester.view.reset);
}

Widget _shell(AssistantApi api) => app(AppShell(
      api: api,
      drive: 'did:ad:drive',
      warmPool: (_) => null,
      profile: (_) => const Scaffold(body: Text('profile page')),
      home: ChatsScreen(drive: 'did:ad:drive', api: api),
    ));

ShellController _controller(WidgetTester tester) =>
    tester.widget<ShellScope>(find.byType(ShellScope)).controller;

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  testWidgets('before the identity is known: the person icon', (tester) async {
    _size(tester, const Size(360, 800));
    await tester.pumpWidget(_shell(_Api(null)));
    await tester.pump();
    expect(find.byIcon(Icons.person_outline), findsOneWidget);
    expect(find.byType(ProfileAvatar), findsNothing);
  });

  testWidgets('a wide phone bar: avatar initial and the name', (tester) async {
    // Next to the pages (600 dp and up) every slot is the same: no name.
    _size(tester, const Size(560, 900));
    await tester.pumpWidget(_shell(_Api(const ProfileIdentity(name: 'Joep'))));
    await tester.pump();
    await tester.pump();
    expect(find.byType(ProfileAvatar), findsOneWidget);
    expect(
        find.descendant(
            of: find.byType(AppBottomBar), matching: find.text('J')),
        findsOneWidget);
    expect(
        find.descendant(
            of: find.byType(AppBottomBar), matching: find.text('Joep')),
        findsOneWidget);
    expect(find.byIcon(Icons.person_outline), findsNothing);
    final size = tester.getSize(find.byTooltip('Joep'));
    expect(size.height, greaterThanOrEqualTo(48));
  });

  testWidgets('a phone at 360 dp: the avatar only, the name as tooltip',
      (tester) async {
    _size(tester, const Size(360, 800));
    await tester.pumpWidget(_shell(_Api(const ProfileIdentity(name: 'Joep'))));
    await tester.pump();
    await tester.pump();
    expect(find.byType(ProfileAvatar), findsOneWidget);
    expect(
        find.descendant(
            of: find.byType(AppBottomBar), matching: find.text('Joep')),
        findsNothing);
    expect(find.byTooltip('Joep'), findsOneWidget);
    final size = tester.getSize(find.byTooltip('Joep'));
    expect(size.width, greaterThanOrEqualTo(48));
    expect(size.height, greaterThanOrEqualTo(48));
    expect(tester.takeException(), isNull);
  });

  testWidgets('an emoji stands in for the initial', (tester) async {
    _size(tester, const Size(360, 800));
    await tester.pumpWidget(
        _shell(_Api(const ProfileIdentity(name: 'Joep', emoji: '🎸'))));
    await tester.pump();
    await tester.pump();
    expect(find.text('🎸'), findsOneWidget);
  });

  testWidgets('a picture that does not load falls back to the initial',
      (tester) async {
    _size(tester, const Size(360, 800));
    await tester.pumpWidget(_shell(_Api(const ProfileIdentity(
        name: 'Joep', imageUrl: 'http://localhost/none.png'))));
    await tester.pump();
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));
    expect(find.byType(Image), findsOneWidget);
    expect(find.text('J'), findsOneWidget);
  });

  testWidgets('the profile page opens from it and the avatar rings while there',
      (tester) async {
    _size(tester, const Size(360, 800));
    await tester.pumpWidget(_shell(_Api(const ProfileIdentity(name: 'Joep'))));
    await tester.pump();
    await tester.pump();
    await tester.tap(find.byTooltip('Joep'));
    await tester.pumpAndSettle();
    expect(find.text('profile page'), findsOneWidget);
    expect(find.byKey(const ValueKey('current:Profile')), findsOneWidget);
  });

  testWidgets('updates after the profile is edited', (tester) async {
    _size(tester, const Size(560, 900));
    final api = _Api(const ProfileIdentity(name: 'Joep'));
    await tester.pumpWidget(_shell(api));
    await tester.pump();
    await tester.pump();
    await tester.tap(find.byTooltip('Joep'));
    await tester.pumpAndSettle();
    api.who = const ProfileIdentity(name: 'Zed');
    _controller(tester).navigatorKey.currentState!.pop();
    await tester.pumpAndSettle();
    expect(
        find.descendant(
            of: find.byType(AppBottomBar), matching: find.text('Zed')),
        findsOneWidget);
    expect(
        find.descendant(
            of: find.byType(AppBottomBar), matching: find.text('Joep')),
        findsNothing);
  });

  testWidgets('the sync mark sits on the avatar, in the button, and the label '
      'says what runs', (tester) async {
    _size(tester, const Size(360, 800));
    var host = const BackgroundState();
    final activity = BackgroundActivity.instance;
    activity.hostPoller = () => host;
    addTearDown(() => activity.hostPoller = null);
    final handle = tester.ensureSemantics();
    await tester.pumpWidget(_shell(_Api(const ProfileIdentity(name: 'Joep'))));
    await tester.pump();
    await tester.pump();
    final bar = find.byType(AppBottomBar);
    final badge = find.descendant(
        of: bar, matching: find.byKey(const Key('background-activity')));
    expect(badge, findsOneWidget);
    expect(activity.polling, isTrue);

    host = const BackgroundState(total: 1, byKind: {'drives': 1});
    await tester.pump(const Duration(seconds: 1));
    await tester.pump(const Duration(milliseconds: 500));
    await tester.pump(const Duration(milliseconds: 50));
    final button = tester.getRect(find.byTooltip('Joep'));
    final avatar = tester.getRect(find.byType(ProfileAvatar));
    final mark = tester.getRect(badge);
    expect(button.overlaps(mark), isTrue);
    expect(button.contains(mark.topLeft) && button.contains(mark.bottomRight),
        isTrue);
    expect(mark.center.dx, greaterThan(avatar.center.dx));
    expect(mark.center.dy, greaterThan(avatar.center.dy));
    expect(find.bySemanticsLabel('Joep, syncing'), findsOneWidget);

    host = const BackgroundState(lastError: 'Offline');
    await tester.pump(const Duration(seconds: 1));
    await tester.pump(const Duration(seconds: 1));
    expect(find.bySemanticsLabel('Joep, sync problem'), findsOneWidget);
    handle.dispose();
  });
}
