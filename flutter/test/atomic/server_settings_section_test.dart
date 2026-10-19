import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:atomic_app/atomic/widgets/server_settings_section.dart';

/// Dead ports: the section must render from stored state alone. Pointing these
/// at a real server would make the suite depend on one being up.
const _serverA = 'http://localhost:1';
const _serverB = 'http://localhost:2';

Future<void> _pumpSection(WidgetTester tester) async {
  await tester.pumpWidget(const MaterialApp(
    home: Scaffold(body: SingleChildScrollView(child: ServerSettingsSection())),
  ));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('says so when there is no server, rather than looking broken',
      (tester) async {
    SharedPreferences.setMockInitialValues({});

    await _pumpSection(tester);

    expect(find.textContaining('No other devices'), findsOneWidget);
    expect(find.text('Connect by address'), findsOneWidget);
  });

  testWidgets('marks the server in use instead of moving it', (tester) async {
    SharedPreferences.setMockInitialValues({
      'atomic_known_servers': [_serverA, _serverB],
      'atomic_server_url': _serverA,
    });

    await _pumpSection(tester);

    // Both stay listed, in the order they were added.
    expect(find.text('localhost:1'), findsOneWidget);
    expect(find.text('localhost:2'), findsOneWidget);

    // Only the active one is marked, and only the other can be switched to.
    expect(find.text('In use'), findsOneWidget);
    expect(find.text('Switch to this'), findsOneWidget);
  });

  testWidgets('every server can be removed, in use or not', (tester) async {
    SharedPreferences.setMockInitialValues({
      'atomic_known_servers': [_serverA, _serverB],
      'atomic_server_url': _serverA,
    });

    await _pumpSection(tester);

    expect(find.text('Remove'), findsNWidgets(2));
  });

  testWidgets('an unreachable server says so, and is still listed',
      (tester) async {
    SharedPreferences.setMockInitialValues({
      'atomic_known_servers': [_serverA],
      'atomic_server_url': _serverA,
    });

    await _pumpSection(tester);

    expect(find.text('localhost:1'), findsOneWidget);
    expect(find.text('Not reachable'), findsOneWidget);
  });

  testWidgets('a server typed without a scheme is remembered normalized',
      (tester) async {
    SharedPreferences.setMockInitialValues({});

    await _pumpSection(tester);
    await tester.tap(find.text('Connect by address'));
    await tester.pumpAndSettle();

    await tester.enterText(find.byType(TextField), 'localhost:1');
    await tester.tap(find.text('Add'));
    await tester.pumpAndSettle();

    final prefs = await SharedPreferences.getInstance();
    expect(prefs.getStringList('atomic_known_servers'), ['http://localhost:1']);
  });
}
