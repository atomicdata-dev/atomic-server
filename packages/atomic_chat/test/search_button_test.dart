import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'assistant_screens_test.dart' show FakeApi, app;

/// The Search button always starts the search over: an empty field, the
/// recents, the focus and the keyboard, on a phone and on the tablet rail.

const _landscape = Size(1280, 800);

RecentResource _r(String subject, String title) => (
      subject: subject,
      title: title,
      className: 'document-v2',
      openedAt: 1,
      emoji: null,
    );

FakeApi _api() => FakeApi(recent: [
      _r('did:ad:plans', 'Plans')
    ], hits: const [
      (
        subject: 'did:ad:abc',
        title: 'Abc result',
        className: 'document-v2',
        drive: 'did:ad:drive',
        score: 1.0,
        emoji: null
      ),
    ]);

Widget _shell(FakeApi api) => app(AppShell(
      api: api,
      drive: 'did:ad:drive',
      warmPool: (_) => null,
      home: ChatsScreen(drive: 'did:ad:drive', api: api),
    ));

/// The Search button of the bar or the rail.
Finder _button() => find.byTooltip('Search').first;

Future<void> _typeAbc(WidgetTester tester) async {
  await tester.enterText(find.byType(TextField), 'abc');
  await tester.pump(const Duration(milliseconds: 100));
  expect(find.text('Abc result'), findsOneWidget);
}

bool _keyboardAsked(WidgetTester tester) =>
    tester.testTextInput.log.any((c) => c.method == 'TextInput.show');

void _expectStartedOver(WidgetTester tester) {
  final field = tester.widget<TextField>(find.byType(TextField));
  expect(field.controller!.text, isEmpty);
  expect(field.focusNode!.hasFocus, isTrue);
  expect(find.text('Abc result'), findsNothing, reason: 'results reset');
  expect(_keyboardAsked(tester), isTrue);
}

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  testWidgets('phone: Search on the open search empties it, keyboard up',
      (tester) async {
    await tester.pumpWidget(_shell(_api()));
    await tester.pumpAndSettle();
    await tester.tap(_button());
    await tester.pumpAndSettle();
    await _typeAbc(tester);

    // The field lost the focus (keyboard put away), then Search again.
    FocusManager.instance.primaryFocus?.unfocus();
    await tester.pump();
    tester.testTextInput.log.clear();
    await tester.tap(_button());
    await tester.pumpAndSettle();
    expect(find.byType(SearchScreen), findsOneWidget);
    _expectStartedOver(tester);
  });

  testWidgets(
      'phone: Search from a page opened out of a search goes back to '
      'it, empty', (tester) async {
    final api = _api();
    await tester.pumpWidget(_shell(api));
    await tester.pumpAndSettle();
    await tester.tap(_button());
    await tester.pumpAndSettle();
    await _typeAbc(tester);
    final shell = tester.widget<ShellScope>(find.byType(ShellScope)).controller;
    // A page over the search (as a result opens one).
    shell.openPage<void>(
        ShellPage.settings, (_) => const Scaffold(body: Text('a page')));
    await tester.pumpAndSettle();
    expect(find.text('a page'), findsOneWidget);

    tester.testTextInput.log.clear();
    await tester.tap(_button());
    await tester.pumpAndSettle();
    expect(find.text('a page'), findsNothing);
    expect(shell.pages, hasLength(1), reason: 'not a second search');
    _expectStartedOver(tester);
  });

  testWidgets('phone: back to the search brings the keyboard back',
      (tester) async {
    await tester.pumpWidget(_shell(_api()));
    await tester.pumpAndSettle();
    await tester.tap(_button());
    await tester.pumpAndSettle();
    await _typeAbc(tester);
    final shell = tester.widget<ShellScope>(find.byType(ShellScope)).controller;
    shell.openPage<void>(
        ShellPage.settings, (_) => const Scaffold(body: Text('a page')));
    await tester.pumpAndSettle();
    tester.testTextInput.log.clear();
    await tester.binding.handlePopRoute();
    await tester.pumpAndSettle();
    final field = tester.widget<TextField>(find.byType(TextField));
    expect(field.controller!.text, 'abc', reason: 'back keeps the query');
    expect(field.focusNode!.hasFocus, isTrue);
    expect(_keyboardAsked(tester), isTrue);
  });

  testWidgets('a new search never has the last query', (tester) async {
    await tester.pumpWidget(_shell(_api()));
    await tester.pumpAndSettle();
    await tester.tap(_button());
    await tester.pumpAndSettle();
    await _typeAbc(tester);
    await tester.tap(find.byTooltip('Home').first);
    await tester.pumpAndSettle();
    await tester.tap(_button());
    await tester.pumpAndSettle();
    final field = tester.widget<TextField>(find.byType(TextField));
    expect(field.controller!.text, isEmpty);
  });

  testWidgets('tablet rail: Search on the open search empties it, keyboard up',
      (tester) async {
    tester.view.devicePixelRatio = 2;
    tester.view.physicalSize = _landscape * 2;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(_shell(_api()));
    await tester.pumpAndSettle();
    await tester.tap(_button());
    await tester.pumpAndSettle();
    await _typeAbc(tester);
    FocusManager.instance.primaryFocus?.unfocus();
    await tester.pump();
    tester.testTextInput.log.clear();
    await tester.tap(_button());
    await tester.pumpAndSettle();
    _expectStartedOver(tester);
  });

  testWidgets('a scoped search keeps its drive; a second tap lets go of it',
      (tester) async {
    await tester.pumpWidget(_shell(_api()));
    await tester.pumpAndSettle();
    final shell = tester.widget<ShellScope>(find.byType(ShellScope)).controller;
    shell.open<void>(
        ShellPage.searchIn('did:ad:work'),
        (settings) => SearchScreen.route(
            drive: 'did:ad:drive',
            api: _api(),
            scopeDrive: 'did:ad:work',
            settings: settings));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('search-scope')), findsOneWidget);
    await tester.enterText(find.byType(TextField), 'abc');
    await tester.pump(const Duration(milliseconds: 100));

    await tester.tap(_button());
    await tester.pumpAndSettle();
    expect(tester.widget<TextField>(find.byType(TextField)).controller!.text,
        isEmpty);
    expect(find.byKey(const Key('search-scope')), findsOneWidget,
        reason: 'only the text goes');

    await tester.tap(_button());
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('search-scope')), findsNothing,
        reason: 'an empty field: the drive goes too');
  });
}
