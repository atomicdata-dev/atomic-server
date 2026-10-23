import 'package:atomic_store/atomic_store.dart';
import 'package:atomic_store/testing.dart';
import 'package:atomic_store_flutter/atomic_store_flutter.dart';
import 'package:atomic_store_flutter/testing.dart';
import 'package:flutter/material.dart';
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

Future<void> openSheet(WidgetTester tester, FakeNode node) async {
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
  testWidgets('the button opens the sheet', (tester) async {
    final node = newNode();
    await tester.runAsync(() => node.identity.create('Alice'));
    await openSheet(tester, node);
    await tester.pumpAndSettle();
    expect(find.text('Alice'), findsOneWidget);
    expect(find.text('Only on this device'), findsOneWidget);
    expect(find.text('Sign in'), findsOneWidget);
  });

  testWidgets('the name follows the agent when another device changes it',
      (tester) async {
    final node = newNode();
    await tester.runAsync(() => node.identity.create('Alice'));
    await openSheet(tester, node);
    await real(tester, () async {});
    expect(find.text('Alice'), findsOneWidget);

    // Another device of the same agent renames it: no button is pressed here.
    await real(tester, () async => node.identity.changeProfileElsewhere('Bob'));
    expect(find.text('Bob'), findsOneWidget);
    expect(find.text('Alice'), findsNothing);
  });

  testWidgets('the name follows the account signed in after a sign-in',
      (tester) async {
    final node = newNode();
    await tester.runAsync(() => node.identity.create('Alice'));
    await openSheet(tester, node);

    await tester.tap(find.text('Sign in').first);
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField).first, 'other-secret');
    await tester.tap(find.widgetWithText(FilledButton, 'Sign in'));
    await real(tester, () async {});

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
    await openSheet(tester, node);

    await tester.tap(find.text('Sign in').first);
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField).first, 'other-secret');
    await tester.tap(find.widgetWithText(FilledButton, 'Sign in'));
    await real(tester, () async {});

    expect(
        find.text(
            'You are signed in. Added to your account: "Notes" and "Recipes".'),
        findsOneWidget);
  });

  testWidgets('a wrong secret says so', (tester) async {
    final node = newNode();
    await openSheet(tester, node);
    await tester.tap(find.text('Sign in').first);
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField).first, 'nope');
    await tester.tap(find.widgetWithText(FilledButton, 'Sign in'));
    await real(tester, () async {});
    expect(find.text('Not an agent secret'), findsOneWidget);
  });

  testWidgets('sharing without a server explains it in one line',
      (tester) async {
    final node = newNode();
    await tester.runAsync(() => node.identity.create('Alice'));
    await openSheet(tester, node);
    await tester.tap(find.text('Share this drive'));
    await tester.pumpAndSettle();
    expect(
        find.text(
            'Sharing needs a server, and this app is not connected to one.'),
        findsOneWidget);
    expect(find.text('Copy invite link'), findsNothing);
  });

  testWidgets('with a server the invite link is offered', (tester) async {
    final node = newNode();
    node.sync.servers.add('https://s.example');
    await tester.runAsync(() async {
      await node.identity.create('Alice');
      await node.sync.connect('https://s.example');
    });
    await openSheet(tester, node);
    await tester.tap(find.text('Share this drive'));
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
    await openSheet(tester, node);
    await tester.tap(find.text('Add a device'));
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
    await openSheet(tester, node);

    await tester.tap(find.widgetWithText(TextButton, 'Sign out'));
    await tester.pumpAndSettle();
    expect(find.text('Sign out?'), findsOneWidget);
    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
    expect(node.identity.secret, isNotNull);

    await tester.tap(find.widgetWithText(TextButton, 'Sign out'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Sign out'));
    await real(tester, () async {});
    expect(node.identity.secret, isNull);
    expect(find.text('Signed out'), findsOneWidget);
  });

  testWidgets('drives: the current one is marked, others switch, new ones add',
      (tester) async {
    final node = newNode();
    await tester.runAsync(() async {
      await node.identity.create('Alice');
      await node.drives.create('Home');
      await node.drives.create('Work');
    });
    await openSheet(tester, node);
    final workDrive = node.store.drive;
    await tester.tap(find.text('Home'));
    await real(tester, () async {});
    expect(node.store.drive, isNot(workDrive));

    await tester.tap(find.text('New drive'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField).last, 'Garden');
    await tester.tap(find.text('Create'));
    await real(tester, () async {});
    expect(find.text('Garden'), findsOneWidget);
  });
}
