import 'dart:async';
import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

class TestBackend extends AtomicSettingsBackend {
  String active = 'drive-a';
  bool failSwitch = false;
  bool failLoad = false;
  int exports = 0;
  int paired = 0;
  final names = {'drive-a': 'Music', 'drive-b': 'Drawings'};
  Completer<List<String>>? pending;
  @override
  Future<AtomicIdentity?> getActiveAgent() async =>
      const AtomicIdentity(subject: 'did:ad:test', name: 'Musician');
  @override
  Future<String> exportSecret() async {
    exports++;
    return 'test-secret';
  }

  @override
  Future<List<String>> listDrives() async {
    if (failLoad) throw StateError('Drive store unavailable');
    return pending == null ? names.keys.toList() : pending!.future;
  }

  @override
  String? getActiveDrive() => active;
  @override
  Future<String> getDriveName(String drive) async => names[drive]!;
  @override
  Future<void> createDrive(String name) async {
    names['drive-${names.length}'] = name;
  }

  @override
  Future<void> switchDrive(String drive) async {
    if (failSwitch) throw StateError('Drive switch failed');
    active = drive;
  }

  @override
  Future<String?> getPeerId() async => 'short-id';
  @override
  Future<String> getDeviceName() async =>
      'A very long tablet device name that must fit on a narrow screen';
  @override
  Future<void> setDeviceName(String name) async {}
  @override
  Future<List<Map<String, String>>> getKnownPeers() async => [];
  @override
  Future<Set<String>> livePeerIds() async => {};
  @override
  Future<void> removeKnownPeer(String nodeId) async {}
  @override
  Future<void> pair(BuildContext context) async {
    paired++;
  }
}

Future<void> showSettings(WidgetTester tester, TestBackend backend) async {
  await tester.pumpWidget(MaterialApp(
      home: Scaffold(
          body: Builder(
              builder: (context) => TextButton(
                    onPressed: () =>
                        AgentSettingsDialog.show(context, backend: backend),
                    child: const Text('User'),
                  )))));
  await tester.tap(find.text('User'));
  await tester.pumpAndSettle();
}

void main() {
  test('canonical peer identifiers match the same legacy node', () {
    final id = 'a' * 64;
    expect(isLiveAtomicPeer('atomic:node:$id', {'did:ad:node:$id'}), isTrue);
  });

  testWidgets('Canvas dialog works at phone width and switches/creates drives',
      (tester) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final backend = TestBackend();
    await showSettings(tester, backend);
    expect(find.text('Identity'), findsOneWidget);
    expect(find.text('Drives'), findsOneWidget);
    expect(find.text('Connect by address'), findsNothing);
    expect(find.text('Sign out'), findsNothing);
    expect(backend.exports, 0);
    expect(tester.takeException(), isNull);
    await tester.tap(find.text('Pair with QR code'));
    await tester.pumpAndSettle();
    expect(backend.paired, 1);
    await tester.ensureVisible(find.text('Drawings'));
    await tester.tap(find.text('Drawings'));
    await tester.pumpAndSettle();
    expect(backend.active, 'drive-b');
    await tester.ensureVisible(find.text('New drive'));
    await tester.tap(find.text('New drive'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'New music');
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await tester.pumpAndSettle();
    expect(backend.names.values, contains('New music'));
    expect(find.text('New music'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets(
      'failed drive selection preserves the active drive and reports error',
      (tester) async {
    final backend = TestBackend()..failSwitch = true;
    await showSettings(tester, backend);
    await tester.ensureVisible(find.text('Drawings'));
    await tester.tap(find.text('Drawings'));
    await tester.pumpAndSettle();
    expect(backend.active, 'drive-a');
    expect(find.textContaining('Failed to switch drive'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('load error offers retry and recovers', (tester) async {
    final backend = TestBackend()..failLoad = true;
    await showSettings(tester, backend);
    expect(find.textContaining('Drive store unavailable'), findsOneWidget);
    backend.failLoad = false;
    await tester.tap(find.text('Retry'));
    await tester.pumpAndSettle();
    expect(find.text('Musician'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('closing during load does not update a disposed dialog',
      (tester) async {
    final backend = TestBackend()..pending = Completer<List<String>>();
    await tester.pumpWidget(MaterialApp(
        home: Scaffold(body: AgentSettingsDialog(backend: backend))));
    await tester.pump();
    await tester.pumpWidget(const SizedBox());
    backend.pending!.complete(['drive-a']);
    await tester.pump();
    expect(tester.takeException(), isNull);
  });

  test('peer identifiers match between Atomic DID and Iroh forms', () {
    final id = List.filled(64, 'a').join();
    expect(isLiveAtomicPeer('did:ad:node:$id', {'iroh:$id'}), isTrue);
    expect(isLiveAtomicPeer('did:ad:node:$id:relay', {id}), isTrue);
  });
}
