import 'dart:async';
import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

class TestBackend extends AtomicSettingsBackend {
  String active = 'drive-a';
  bool failSwitch = false;
  bool failLoad = false;
  int exports = 0;
  int paired = 0;
  final names = {'drive-a': 'Music', 'drive-b': 'Drawings'};
  Completer<List<String>>? pending;
  bool signingIn = false;
  bool inviting = false;
  bool failInvite = false;
  String? signedInWith;
  @override
  Future<String> Function(String secret)? get signInWithSecret => signingIn
      ? (secret) async {
          signedInWith = secret;
          return 'You are signed in.';
        }
      : null;
  @override
  Future<String> Function({required bool canEdit})? get inviteLink => inviting
      ? ({required canEdit}) async {
          if (failInvite) throw StateError('Sharing needs a server.');
          return 'https://invite.example/${canEdit ? 'edit' : 'read'}';
        }
      : null;
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
                        showAtomicUserDialog(context, backend: backend),
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

  testWidgets('the panel works at phone width and switches/creates workspaces',
      (tester) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final backend = TestBackend();
    await showSettings(tester, backend);
    expect(find.text('Musician'), findsOneWidget);
    expect(find.text('Music'), findsOneWidget);
    expect(find.text('Connect by address'), findsNothing);
    expect(find.text('Sign out'), findsNothing);
    // Closed until asked for: nothing about secrets or signing in.
    expect(find.text('Sign in with a secret key'), findsNothing);
    expect(backend.exports, 0);
    expect(tester.takeException(), isNull);
    await tester.tap(find.text('Pair with QR code'));
    await tester.pumpAndSettle();
    expect(backend.paired, 1);
    await tester.tap(find.text('Workspace'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Drawings'));
    await tester.pumpAndSettle();
    expect(backend.active, 'drive-b');
    expect(find.text('Drawings'), findsOneWidget);
    await tester.tap(find.text('Workspace'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('New workspace'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'New music');
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await tester.pumpAndSettle();
    expect(backend.names.values, contains('New music'));
    expect(tester.takeException(), isNull);
  });

  testWidgets('a workspace without a name is called Workspace', (tester) async {
    final backend = TestBackend()..names['drive-a'] = '';
    await showSettings(tester, backend);
    expect(find.text('Workspace'), findsNWidgets(2));
  });

  testWidgets('failed workspace switch keeps the active one and says so',
      (tester) async {
    final backend = TestBackend()..failSwitch = true;
    await showSettings(tester, backend);
    await tester.tap(find.text('Workspace'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Drawings'));
    await tester.pumpAndSettle();
    expect(backend.active, 'drive-a');
    expect(find.textContaining('Could not switch workspace'), findsWidgets);
    expect(tester.takeException(), isNull);
  });

  testWidgets('a load error is shown', (tester) async {
    final backend = TestBackend()..failLoad = true;
    await showSettings(tester, backend);
    expect(find.textContaining('Drive store unavailable'), findsOneWidget);
  });

  testWidgets('secret and sign in stay closed until tapped, then work',
      (tester) async {
    tester.view.physicalSize = const Size(390, 1600);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
    final backend = TestBackend()..signingIn = true;
    await showSettings(tester, backend);
    expect(find.byType(TextField), findsNothing);
    expect(find.text('test-secret'), findsNothing);
    await tester.tap(find.text('Show secret key'));
    await tester.pumpAndSettle();
    expect(find.text('test-secret'), findsOneWidget);
    await tester.tap(find.text('Sign in with a secret key'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'other');
    await tester.tap(find.text('Sign in'));
    await tester.pumpAndSettle();
    expect(backend.signedInWith, 'other');
    expect(find.text('You are signed in.'), findsOneWidget);
    expect(find.text('test-secret'), findsNothing);
  });

  testWidgets('the invite row copies a link for the chosen access',
      (tester) async {
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
        SystemChannels.platform, (call) async => null);
    addTearDown(() => tester.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, null));
    final backend = TestBackend()..inviting = true;
    await showSettings(tester, backend);
    await tester.tap(find.text('Invite someone'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Can edit'));
    await tester.tap(find.text('Copy invite link'));
    await tester.pumpAndSettle();
    expect(find.text('https://invite.example/edit'), findsOneWidget);
  });

  Future<void> openDialog(WidgetTester tester, TestBackend backend) async {
    await tester.pumpWidget(MaterialApp(
      home: Scaffold(
        body: Builder(
          builder: (context) => TextButton(
            onPressed: () => showAtomicUserDialog(context, backend: backend),
            child: const Text('Open'),
          ),
        ),
      ),
    ));
    await tester.tap(find.text('Open'));
    await tester.pumpAndSettle();
  }

  void expectOnceInDialog(WidgetTester tester, String text) {
    final shown = find.textContaining(text);
    expect(shown, findsOneWidget);
    expect(find.descendant(of: find.byType(Dialog), matching: shown),
        findsOneWidget);
    expect(find.textContaining('Bad state'), findsNothing);
  }

  testWidgets('a failed invite shows once, inside the dialog, without prefix',
      (tester) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final backend = TestBackend()
      ..inviting = true
      ..failInvite = true;
    await openDialog(tester, backend);
    await tester.tap(find.text('Invite someone'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Copy invite link'));
    await tester.pumpAndSettle();
    expectOnceInDialog(tester, 'Could not make the link: Sharing needs');
  });

  testWidgets('a panel snack in the dialog stays in it, not on the host',
      (tester) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final backend = TestBackend()..failSwitch = true;
    await openDialog(tester, backend);
    await tester.tap(find.text('Workspace'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Drawings'));
    await tester.pumpAndSettle();
    expectOnceInDialog(tester, 'Could not switch workspace: Drive switch');
    expect(find.byType(SnackBar), findsOneWidget);
  });

  test('cleanError drops Dart exception prefixes', () {
    expect(cleanError('Bad state: x'), 'x');
    expect(cleanError('Could not: Exception: x'), 'Could not: x');
  });

  testWidgets('closing during load does not update a disposed panel',
      (tester) async {
    final backend = TestBackend()..pending = Completer<List<String>>();
    await tester.pumpWidget(
        MaterialApp(home: Scaffold(body: AtomicUserPanel(backend: backend))));
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
