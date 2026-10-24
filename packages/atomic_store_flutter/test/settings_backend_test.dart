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

  testWidgets('without a server the invite link needs no server address',
      (tester) async {
    final node = newNode();
    await tester.runAsync(() => node.identity.create('Alice'));
    await openPanel(tester, node);
    await tester.tap(find.text('Invite someone'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Copy invite link'));
    await real(tester, () async {});
    expect(find.textContaining('atomic:invite?token='), findsOneWidget);
    expect(find.textContaining('Sharing needs a server'), findsNothing);
    expect(node.peers.nodeId, isNotNull,
        reason: 'this device must announce itself for the link to work');
  });

  testWidgets('Open an invite is only offered when the node can accept',
      (tester) async {
    final node = newNode();
    await tester.runAsync(() => node.identity.create('Alice'));
    await openPanel(tester, node);
    expect(find.text('Open an invite'), findsNothing);
  });

  testWidgets('Open an invite joins the drive, switches to it and says so',
      (tester) async {
    const shared = 'did:ad:test:shared';
    final tokens = <String>[];
    final node = FakeNode(
      Store(
          backend: InMemoryBackend({
            drive: {Props.name: const StringValue('Home')}
          }),
          drive: drive),
      drives: const [DriveInfo(subject: shared, name: 'Band')],
      acceptInvite: (token) async {
        tokens.add(token);
        return const AcceptedInvite(drive: shared, write: true);
      },
    );
    await tester.runAsync(() => node.identity.create('Alice'));
    await openPanel(tester, node);
    await tester.tap(find.text('Open an invite'));
    await tester.pumpAndSettle();
    await tester.enterText(
        find.byType(TextField), 'atomic:invite?token=abc%2Bdef%3D%3D');
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await real(tester, () async {});
    expect(tokens, ['abc+def==']);
    expect(node.store.drive, shared);
    expect(find.textContaining('You can now edit "Band", and it is open.'),
        findsOneWidget);
  });

  testWidgets('Open an invite says why a link does not work', (tester) async {
    final node = FakeNode(
      Store(backend: InMemoryBackend(), drive: drive),
      acceptInvite: (token) async => throw const StoreException(
          StoreErrorKind.network,
          'The device that made this invite is offline. Ask them to open the app, then try again.'),
    );
    await tester.runAsync(() => node.identity.create('Alice'));
    await openPanel(tester, node);
    await tester.tap(find.text('Open an invite'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'atomic:invite?token=abc');
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await real(tester, () async {});
    expect(find.textContaining('The device that made this invite is offline'),
        findsOneWidget);
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
    // The panel grew (longer device-name hint): scroll the button into view.
    await tester.drag(find.byType(Scrollable).first, const Offset(0, -300));
    await tester.pumpAndSettle();
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

  testWidgets('a connected device reads as up to date, and follows',
      (tester) async {
    final node = newNode();
    final peers = node.peers;
    peers.status = const PeerSearchStatus('connected');
    const other =
        'aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11';
    peers.add(other, 'Mac.home');
    await openPanel(tester, node);
    expect(find.textContaining('Not synced yet'), findsOneWidget);

    peers.connect(other);
    await tester.pump(const Duration(seconds: 3));
    await tester.pumpAndSettle();
    expect(find.textContaining('Up to date, syncing live'), findsOneWidget);
    expect(find.textContaining('Not synced yet'), findsNothing);
  });

  testWidgets('your name and the device name are told apart', (tester) async {
    final node = newNode();
    await tester.runAsync(() => node.identity.create('Alice'));
    await openPanel(tester, node);
    // The name is the person's; the device name stays on this device.
    expect(find.text('Edit your name'), findsOneWidget);
    expect(find.text('Edit profile'), findsNothing);
    expect(find.text('Device name, only on this device. Tap to rename.'),
        findsOneWidget);
    expect(find.text('Tap to rename'), findsNothing);
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

  testWidgets('this device shows its node id and the storage used',
      (tester) async {
    final node = newNode();
    node.statsJson = '{"loro_bytes": 3145728, "blob_bytes": 1048576, '
        '"resources": 1200, "disk_bytes": 8388608, "drives": ['
        '{"subject": "did:ad:test:home", "name": "Home", "resources": 1200, '
        '"bytes": 4194304}]}';
    node.deviceJson = '{"version": "1.2.3", "os": "linux", "arch": "arm64"}';
    await tester.runAsync(() => node.peers.start());
    await openPanel(tester, node);
    await real(tester, () async {});

    expect(find.text('This device'), findsWidgets);
    expect(find.text('Fake device'), findsOneWidget);
    expect(find.text('Device name, only on this device. Tap to rename.'),
        findsOneWidget);
    // The node id, shortened, with a copy button that puts all of it away.
    expect(find.text('ffffffffffff…ffffff'), findsOneWidget);
    expect(find.text('Device ID'), findsOneWidget);
    expect(find.byKey(const Key('copy-device-id')), findsOneWidget);
    expect(find.text('1.2.3'), findsOneWidget);
    // Storage used by atomic, and the file on disk.
    expect(find.text('Storage'), findsOneWidget);
    expect(find.textContaining('4.0 MB'), findsWidgets);
    expect(find.text('On disk'), findsOneWidget);
    expect(find.textContaining('8.0 MB'), findsOneWidget);
  });
}
