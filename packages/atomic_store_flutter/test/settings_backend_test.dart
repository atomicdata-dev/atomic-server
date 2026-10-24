import 'package:atomic_store/atomic_store.dart';
import 'package:atomic_store/testing.dart';
import 'package:atomic_store_flutter/atomic_store_flutter.dart';
import 'package:atomic_store_flutter/testing.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

const drive = 'did:ad:test:home';

FakeNode newNode() {
  final backend = InMemoryBackend({
    drive: {Props.name: const StringValue('Home')}
  });
  final node = FakeNode(Store(backend: backend, drive: drive));
  node.identity.known['other-secret'] = (drive: drive, needsSync: false);
  return node;
}

Future<void> openPanel(WidgetTester tester, FakeNode node) async {
  // Unmocked, the clipboard never answers in a test.
  tester.binding.defaultBinaryMessenger
      .setMockMethodCallHandler(SystemChannels.platform, (call) async => null);
  addTearDown(() => tester.binding.defaultBinaryMessenger
      .setMockMethodCallHandler(SystemChannels.platform, null));
  await tester.binding.setSurfaceSize(const Size(600, 2400));
  addTearDown(() => tester.binding.setSurfaceSize(null));
  await tester.pumpWidget(MaterialApp(
      home: Scaffold(
          appBar: AppBar(actions: [AtomicAccountButton(node: node)]))));
  await tester.tap(find.byType(AtomicAccountButton));
  await tester.pumpAndSettle();
}

/// Runs [body] with real async (the fakes use futures), then settles.
Future<void> real(WidgetTester tester, Future<void> Function() body) async {
  await tester.runAsync(() async {
    await body();
    await Future<void>.delayed(const Duration(milliseconds: 20));
  });
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('the button opens the panel with its rows closed',
      (tester) async {
    final node = newNode();
    await tester.runAsync(() => node.identity.create('Alice'));
    await openPanel(tester, node);
    expect(find.text('Alice'), findsOneWidget);
    expect(find.text('Workspace'), findsWidgets);
    expect(find.text('Sign in with a secret key'), findsOneWidget);
    expect(find.byType(TextField), findsNothing);
    expect(find.text(node.identity.secret!), findsNothing);
  });

  testWidgets('the name follows the agent when another device changes it',
      (tester) async {
    final node = newNode();
    await tester.runAsync(() => node.identity.create('Alice'));
    await openPanel(tester, node);
    await real(tester, () async {});
    expect(find.text('Alice'), findsOneWidget);

    // Another device of the same agent renames it: no button is pressed here.
    await real(tester, () async => node.identity.changeProfileElsewhere('Bob'));
    expect(find.text('Bob'), findsOneWidget);
    expect(find.text('Alice'), findsNothing);
  });

  testWidgets('the name is edited here', (tester) async {
    final node = newNode();
    await tester.runAsync(() => node.identity.create('Alice'));
    await openPanel(tester, node);
    await tester.tap(find.text('Alice'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'Alicia');
    await tester.tap(find.text('Save'));
    await real(tester, () async {});
    expect(find.text('Alicia'), findsOneWidget);
  });

  Future<void> signIn(WidgetTester tester, String secret) async {
    await tester.tap(find.text('Sign in with a secret key'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), secret);
    await tester.tap(find.widgetWithText(FilledButton, 'Sign in'));
    await real(tester, () async {});
  }

  testWidgets('the name follows the account signed in after a sign-in',
      (tester) async {
    final node = newNode();
    await tester.runAsync(() => node.identity.create('Alice'));
    await openPanel(tester, node);
    await signIn(tester, 'other-secret');

    await real(
        tester, () async => node.identity.changeProfileElsewhere('Carol'));
    expect(find.text('Carol'), findsOneWidget);
  });

  testWidgets('signing in names the drives that came along', (tester) async {
    final node =
        FakeNode(Store(backend: InMemoryBackend(), drive: drive), drives: [
      const DriveInfo(subject: 'did:ad:test:n', name: 'Notes'),
      const DriveInfo(subject: 'did:ad:test:r', name: 'Recipes'),
    ]);
    node.identity.known['other-secret'] = (drive: drive, needsSync: false);
    await tester.runAsync(() => node.identity.create('Alice'));
    node.identity.work = ['did:ad:test:n', 'did:ad:test:r'];
    await openPanel(tester, node);
    await signIn(tester, 'other-secret');

    expect(
        find.text(
            'You are signed in. Added to your account: "Notes" and "Recipes".'),
        findsOneWidget);
  });

  testWidgets('a wrong secret says so', (tester) async {
    final node = newNode();
    await openPanel(tester, node);
    await signIn(tester, 'nope');
    expect(find.textContaining('Not an agent secret'), findsOneWidget);
  });

  testWidgets('the secret shows only when asked', (tester) async {
    final node = newNode();
    await tester.runAsync(() => node.identity.create('Alice'));
    await openPanel(tester, node);
    await tester.tap(find.text('Show secret key'));
    await real(tester, () async {});
    expect(find.text(node.identity.secret!), findsOneWidget);
    await tester.tap(find.text('Hide secret key'));
    await tester.pumpAndSettle();
    expect(find.text(node.identity.secret!), findsNothing);
  });

  testWidgets('an invite without a server explains it in one line',
      (tester) async {
    final node = newNode();
    await tester.runAsync(() => node.identity.create('Alice'));
    await openPanel(tester, node);
    await tester.tap(find.text('Invite someone'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Copy invite link'));
    await real(tester, () async {});
    expect(
        find.textContaining(
            'Sharing needs a server, and this app is not connected to one.'),
        findsWidgets);
  });

  testWidgets('with a server the invite link is copied', (tester) async {
    final node = newNode();
    node.sync.servers.add('https://s.example');
    await tester.runAsync(() async {
      await node.identity.create('Alice');
      await node.sync.connect('https://s.example');
    });
    await openPanel(tester, node);
    await tester.tap(find.text('Invite someone'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Copy invite link'));
    await real(tester, () async {});
    expect(find.textContaining('https://s.example/app/invite?token='),
        findsOneWidget);
  });

  testWidgets('a code from another device pairs it', (tester) async {
    final node = newNode();
    final other = 'a' * 64;
    node.peers.reachable.add(other);
    await tester.runAsync(() => node.identity.create('Alice'));
    await openPanel(tester, node);
    await tester.tap(find.text('Pair with QR code'));
    await real(tester, () async {});
    expect(find.text(node.peers.pairingCode!), findsOneWidget);

    await tester.enterText(
        find.widgetWithText(TextField, 'Code from another device'),
        PairingCode.format(other, 'Laptop'));
    await tester.tap(find.text('Add device'));
    await real(tester, () async {});
    expect(find.textContaining('Device added'), findsOneWidget);
    expect(node.peers.known.single.nodeId, other);
  });

  testWidgets('signing out asks first', (tester) async {
    final node = newNode();
    await tester.runAsync(() => node.identity.create('Alice'));
    await openPanel(tester, node);

    await tester.tap(find.widgetWithText(OutlinedButton, 'Sign out'));
    await tester.pumpAndSettle();
    expect(find.text('Sign out?'), findsOneWidget);
    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
    expect(node.identity.secret, isNotNull);

    await tester.tap(find.widgetWithText(OutlinedButton, 'Sign out'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(TextButton, 'Sign out'));
    await real(tester, () async {});
    expect(node.identity.secret, isNull);
    expect(find.text('You'), findsOneWidget);
  });

  testWidgets('workspaces: the current one is shown, others switch, new add',
      (tester) async {
    final node = newNode();
    await tester.runAsync(() async {
      await node.identity.create('Alice');
      await node.drives.create('Home');
      await node.drives.create('Work');
    });
    await openPanel(tester, node);
    final workDrive = node.store.drive;
    expect(find.text('Work'), findsOneWidget);
    await tester.tap(find.text('Workspace'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Home'));
    await real(tester, () async {});
    expect(node.store.drive, isNot(workDrive));

    await tester.tap(find.text('Workspace'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('New workspace'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'Garden');
    await tester.tap(find.text('Save'));
    await real(tester, () async {});
    expect(find.text('Garden'), findsOneWidget);
  });
}
