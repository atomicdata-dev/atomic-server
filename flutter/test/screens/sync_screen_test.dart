import 'dart:async';

import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:atomic_flutter/atomic_flutter.dart' show SyncCard;
import 'package:atomic_chat/atomic_chat.dart'
    show ProfileAvatar, ResourceWebView;
import 'package:atomic_app/atomic/account_store.dart';
import 'package:atomic_app/screens/sync_screen.dart';
import 'package:atomic_app/theme.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

class _Servers extends shared.AtomicServerBackend {
  final bool managed;

  /// No server in use, but a managed one is known (paired, not switched to).
  final bool noneActive;
  _Servers({this.managed = false, this.noneActive = false});

  @override
  Future<List<String>> knownServers() async => ['https://node.example'];
  @override
  Future<String?> activeServer() async =>
      noneActive ? null : 'https://node.example';
  @override
  Future<shared.ServerInfo> serverInfo(String url) async => shared.ServerInfo(
        managed: managed,
        portalUrl: managed ? 'https://portal.example' : null,
      );
  @override
  Future<shared.DriveUsage?> driveUsage(String url) async => null;
  @override
  Future<void> switchTo(String url) async {}
  @override
  Future<void> add(String url) async {}
  @override
  Future<void> remove(String url) async {}
  @override
  Future<int> pushWorkspace(String url) async => 0;
}

class _Backend extends shared.AtomicSettingsBackend {
  final shared.AtomicServerBackend? _servers;
  final List<String> switched = [];
  String active = 'did:ad:a';

  /// Whether the profile can be edited natively (the app's backend can).
  final bool editable;
  String name = 'Joep';
  String description = '';
  String? emoji;

  /// What the device card asks for; null leaves the card without it.
  Future<shared.StoreStats?> Function()? stats;
  shared.DeviceInfo? info;
  List<Map<String, String>> peers = [];

  _Backend({shared.AtomicServerBackend? servers, this.editable = false})
      : _servers = servers;

  @override
  Future<shared.StoreStats?> storeStats({bool refresh = false}) async =>
      stats?.call();
  @override
  shared.DeviceInfo? deviceInfo() => info;

  @override
  Future<shared.AtomicIdentity?> getActiveAgent() async =>
      shared.AtomicIdentity(
          subject: 'did:ad:agent',
          name: name,
          description: description,
          emoji: emoji);
  @override
  Future<void> Function({required String name, required String description})?
      get saveProfile => editable
          ? ({required name, required description}) async {
              this.name = name;
              this.description = description;
            }
          : null;
  @override
  Future<String> exportSecret() async => 'secret';
  @override
  Future<List<String>> listDrives() async => ['did:ad:a', 'did:ad:b'];
  @override
  String? getActiveDrive() => active;
  @override
  Future<String> getDriveName(String drive) async =>
      drive == 'did:ad:a' ? 'Private' : 'Team';
  @override
  Future<void> createDrive(String name) async {}
  @override
  Future<void> switchDrive(String drive) async {
    switched.add(drive);
    active = drive;
  }

  @override
  Future<String?> getPeerId() async => 'a1b2c3d4e5f6a7b8c9d0e1f2';
  @override
  Future<String> getDeviceName() async => 'Pixel';
  @override
  Future<void> setDeviceName(String name) async {}
  @override
  Future<List<Map<String, String>>> getKnownPeers() async => peers;
  @override
  Future<Set<String>> livePeerIds() async => {};
  @override
  Future<void> removeKnownPeer(String nodeId) async {}
  @override
  Future<void> pair(BuildContext context) async {}
  @override
  shared.AtomicServerBackend? get servers => _servers;
  @override
  Future<void> Function()? get signOut => () async {};
}

Widget _app(Widget home) => MaterialApp(
      theme: ThemeData(
          brightness: Brightness.dark, extensions: const [AppColors.dark]),
      home: home,
    );

void main() {
  testWidgets('shows the agent, this device and the workspaces; no account',
      (tester) async {
    await tester.pumpWidget(_app(SyncScreen(
      backend: _Backend(),
      loadAccount: (_) async => null,
    )));
    await tester.pumpAndSettle();

    expect(find.text('Joep'), findsOneWidget);
    expect(find.text('J'), findsOneWidget);
    expect(find.text('This device'), findsOneWidget);
    expect(find.text('Pixel'), findsOneWidget);
    expect(find.text('Devices'), findsOneWidget);
    // Only the current workspace shows; the others are in the switcher.
    expect(find.text('Private'), findsOneWidget);
    expect(find.text('Team'), findsNothing);
    expect(find.text('Account'), findsNothing);
    expect(find.text('Link your account'), findsNothing);
  });

  testWidgets('the ID under the name copies it, and says so', (tester) async {
    String? copied;
    tester.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, (call) async {
      if (call.method == 'Clipboard.setData') {
        copied = (call.arguments as Map)['text'] as String?;
      }
      return null;
    });
    addTearDown(() => tester.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, null));
    await tester.pumpWidget(_app(SyncScreen(
      backend: _Backend(),
      loadAccount: (_) async => null,
    )));
    await tester.pumpAndSettle();
    expect(find.byTooltip('Copy ID'), findsOneWidget);
    await tester.tap(find.byKey(const Key('copy-agent-id')));
    await tester.pump();
    expect(copied, 'did:ad:agent');
    await tester.pumpAndSettle(const Duration(seconds: 5));
  });

  testWidgets('tapping the identity opens the agent page', (tester) async {
    String? opened;
    await tester.pumpWidget(_app(SyncScreen(
      backend: _Backend(),
      loadAccount: (_) async => null,
      profilePage: (subject) {
        opened = subject;
        return const Scaffold(body: Text('profile page'));
      },
    )));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Joep'));
    await tester.pumpAndSettle();
    expect(find.text('profile page'), findsOneWidget);
    expect(opened, 'did:ad:agent');
  });

  testWidgets('tapping the identity edits the profile, saved and shown',
      (tester) async {
    final backend = _Backend(editable: true);
    await tester.pumpWidget(_app(SyncScreen(
      backend: backend,
      loadAccount: (_) async => null,
    )));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Joep'));
    await tester.pumpAndSettle();

    expect(find.text('Profile'), findsOneWidget);
    await tester.enterText(find.byKey(const Key('profile-name')), ' Pelican ');
    await tester.enterText(
        find.byKey(const Key('profile-description')), 'Likes fish');
    await tester.tap(find.text('Save'));
    await tester.pumpAndSettle();

    expect(backend.name, 'Pelican');
    expect(backend.description, 'Likes fish');
    // Back on the Sync page, which read the profile again.
    expect(find.text('Profile'), findsNothing);
    expect(find.text('Pelican'), findsOneWidget);
    expect(find.text('P'), findsOneWidget);
  });

  testWidgets('an empty name cannot be saved', (tester) async {
    final backend = _Backend(editable: true);
    await tester.pumpWidget(_app(SyncScreen(
      backend: backend,
      loadAccount: (_) async => null,
    )));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Joep'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('profile-name')), '  ');
    await tester.pump();
    await tester.tap(find.text('Save'));
    await tester.pumpAndSettle();
    expect(find.text('Profile'), findsOneWidget);
    expect(backend.name, 'Joep');
  });

  testWidgets('the identity shows its emoji icon over the initial',
      (tester) async {
    await tester.pumpWidget(_app(SyncScreen(
      backend: _Backend()..emoji = '🦩',
      loadAccount: (_) async => null,
    )));
    await tester.pumpAndSettle();
    expect(find.text('🦩'), findsOneWidget);
    expect(find.text('J'), findsNothing);
  });

  testWidgets('a linked account shows address, vault and server',
      (tester) async {
    await tester.pumpWidget(_app(SyncScreen(
      backend: _Backend(servers: _Servers(managed: true)),
      loadCredits: () async => null,
      loadAccount: (drive) async => AccountSummary(
        address: 'joep@example.org',
        portal: Uri.parse('https://portal.example'),
        vault: const <String, dynamic>{'used_bytes': 2048, 'last_backup_at': 0},
        server: null,
      ),
    )));
    await tester.pumpAndSettle();

    expect(find.text('Account'), findsOneWidget);
    expect(find.text('joep@example.org'), findsOneWidget);
    expect(find.text('Cloud Vault'), findsOneWidget);
    expect(find.textContaining('On · 2.0 KB'), findsOneWidget);
    expect(find.text('Off for Private'), findsOneWidget);
    expect(find.text('Link your account'), findsNothing);
  });

  testWidgets('a managed server offers to link the account', (tester) async {
    String? linked;
    await tester.pumpWidget(_app(SyncScreen(
      backend: _Backend(servers: _Servers(managed: true)),
      loadAccount: (_) async => null,
      linkAccount: (context, portal) async => linked = portal,
    )));
    await tester.pumpAndSettle();

    await tester.tap(find.text('Link your account'));
    await tester.pumpAndSettle();
    expect(linked, 'https://portal.example');
  });

  testWidgets('a known managed server offers the link without being active',
      (tester) async {
    await tester.pumpWidget(_app(SyncScreen(
      backend: _Backend(servers: _Servers(managed: true, noneActive: true)),
      loadAccount: (_) async => null,
      linkAccount: (context, portal) async {},
    )));
    await tester.pumpAndSettle();
    expect(find.text('Link your account'), findsOneWidget);
  });

  testWidgets('a self-hosted server never offers an account', (tester) async {
    await tester.pumpWidget(_app(SyncScreen(
      backend: _Backend(servers: _Servers()),
      loadAccount: (_) async => null,
    )));
    await tester.pumpAndSettle();
    expect(find.text('Link your account'), findsNothing);
    expect(find.text('Account'), findsNothing);
  });

  testWidgets('switching workspace goes through the backend', (tester) async {
    final backend = _Backend();
    await tester.pumpWidget(_app(SyncScreen(
      backend: backend,
      loadAccount: (_) async => null,
    )));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Private'));
    await tester.pumpAndSettle();
    expect(find.text('Team'), findsOneWidget);
    await tester.tap(find.text('Team'));
    await tester.pumpAndSettle();
    expect(backend.switched, ['did:ad:b']);
  });

  Future<ResourceWebView?> openPortal(
      WidgetTester tester, Future<String?> Function(Uri) cookie) async {
    ResourceWebView? opened;
    await tester.pumpWidget(_app(SyncScreen(
      backend: _Backend(servers: _Servers(managed: true)),
      loadAccount: (_) async => AccountSummary(
        address: 'joep@example.org',
        portal: Uri.parse('https://portal.example'),
      ),
      loadCredits: () async => null,
      portalCookie: cookie,
      portalPage: (page) {
        opened = page;
        return const Scaffold(body: Text('portal page'));
      },
    )));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.text('Manage in the portal'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Manage in the portal'));
    await tester.pumpAndSettle();
    return opened;
  }

  testWidgets('the portal opens signed in with the agent cookie',
      (tester) async {
    Uri? asked;
    final page = await openPortal(tester, (portal) async {
      asked = portal;
      return 'abc123';
    });
    expect(asked!.origin, 'https://portal.example');
    expect(page!.url, 'https://portal.example/dashboard');
    expect(page.injectCss, contains('nav.topbar'));
    expect(find.text('portal page'), findsOneWidget);
    expect(page.cookies, hasLength(1));
    expect(page.cookies.single.name, 'session_token');
    expect(page.cookies.single.value, 'abc123');
    expect(page.cookies.single.domain, 'portal.example');
    expect(page.keepOnHost, isTrue);
  });

  testWidgets('without a cookie the portal still opens', (tester) async {
    final page = await openPortal(tester, (_) async => null);
    expect(find.text('portal page'), findsOneWidget);
    expect(page!.cookies, isEmpty);
  });

  group('AI credits', () {
    Widget app(Future<shared.AtomicAiCredits?> Function() load) =>
        _app(SyncScreen(
          backend: _Backend(servers: _Servers(managed: true)),
          loadAccount: (_) async => AccountSummary(
            address: 'joep@example.org',
            portal: Uri.parse('https://portal.example'),
          ),
          loadCredits: load,
        ));

    testWidgets('shows the balance and refreshes on demand', (tester) async {
      var remaining = 5000;
      await tester.pumpWidget(app(() async => shared.AtomicAiCredits(
            enabled: true,
            allowanceMicros: 10000,
            remainingMicros: remaining,
            purchasedMicros: 2000,
            purchasesEnabled: true,
          )));
      await tester.pumpAndSettle();
      await tester.scrollUntilVisible(find.text('AI credits'), 300);
      expect(find.text('5 of 10 this month · 2 purchased'), findsOneWidget);
      expect(find.text('Get more credits'), findsOneWidget);
      remaining = 3000;
      await tester.tap(find.byTooltip('Refresh AI credits'));
      await tester.pumpAndSettle();
      expect(find.text('3 of 10 this month · 2 purchased'), findsOneWidget);
    });

    testWidgets('offline keeps the last known balance', (tester) async {
      var fail = false;
      await tester.pumpWidget(app(() async {
        if (fail) throw StateError('offline');
        return const shared.AtomicAiCredits(
            enabled: true, allowanceMicros: 10000, remainingMicros: 4000);
      }));
      await tester.pumpAndSettle();
      await tester.scrollUntilVisible(find.text('AI credits'), 300);
      fail = true;
      await tester.tap(find.byTooltip('Refresh AI credits'));
      await tester.pumpAndSettle();
      expect(find.text('4 of 10 this month · offline, last known'),
          findsOneWidget);
      expect(find.text('Get more credits'), findsNothing);
    });

    testWidgets('shows a dash before anything is known', (tester) async {
      await tester.pumpWidget(app(() async => null));
      await tester.pumpAndSettle();
      await tester.scrollUntilVisible(find.text('AI credits'), 300);
      expect(find.text('—'), findsOneWidget);
    });
  });

  group('This device card', () {
    setUp(() => SharedPreferences.setMockInitialValues({}));
    final stats = shared.StoreStats.fromJson({
      'resources': 1700,
      'loro_bytes': 3 * 1024 * 1024,
      'blob_bytes': 1024 * 1024,
      'disk_bytes': 9 * 1024 * 1024,
      'drives': [
        {
          'subject': 'did:ad:b',
          'name': 'Team',
          'resources': 200,
          'bytes': 1024 * 1024
        },
        {
          'subject': 'did:ad:a',
          'name': 'Archive',
          'resources': 1500,
          'bytes': 3 * 1024 * 1024
        },
      ],
    })!;

    _Backend full() => _Backend()
      ..stats = (() async => stats)
      ..info = const shared.DeviceInfo(
          platform: 'Android', appVersion: '0.41.0', arch: 'aarch64')
      ..peers = [
        {'node_id': 'n1', 'name': 'Laptop', 'last_synced': '1700000000000'},
      ];

    Future<void> pumpScreen(WidgetTester tester, _Backend backend,
        {Size size = const Size(393, 852),
        double scale = 1,
        Brightness brightness = Brightness.dark,
        Widget Function(String, String)? storagePage}) async {
      tester.view.physicalSize = size;
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.reset);
      await tester.pumpWidget(MaterialApp(
        theme: ThemeData(brightness: brightness, extensions: [
          brightness == Brightness.dark ? AppColors.dark : AppColors.light
        ]),
        builder: (context, child) => MediaQuery(
            data: MediaQuery.of(context)
                .copyWith(textScaler: TextScaler.linear(scale)),
            child: child!),
        home: SyncScreen(
            backend: backend,
            loadAccount: (_) async => null,
            storagePage: storagePage),
      ));
      await tester.pumpAndSettle();
    }

    Future<void> showStorage(WidgetTester tester) async {
      await tester.ensureVisible(find.byKey(const Key('stats-total')));
      await tester.pumpAndSettle();
    }

    testWidgets('shows name, platform, version and the storage total',
        (tester) async {
      await pumpScreen(tester, full());

      expect(find.text('Pixel'), findsOneWidget);
      expect(find.text('Android · aarch64'), findsOneWidget);
      expect(find.text('0.41.0'), findsOneWidget);
      await showStorage(tester);
      expect(find.text('4.0 MB · 2 drives'), findsOneWidget);
      expect(find.text('1.7k resources · 1.0 MB files'), findsOneWidget);
      expect(find.text('9.0 MB'), findsOneWidget);
      expect(find.text('Synced with'), findsOneWidget);
      expect(find.text('1 device'), findsOneWidget);
      // The paired device says it does not know how much it holds.
      await tester.scrollUntilVisible(find.text('Data size unknown'), 300,
          scrollable: find.byType(Scrollable).first);
      expect(find.text('Data size unknown'), findsOneWidget);
    });

    testWidgets('the per-drive storage is collapsed until the row is tapped',
        (tester) async {
      await pumpScreen(tester, full());
      await showStorage(tester);
      expect(find.byKey(const ValueKey('drive-row-did:ad:a')), findsNothing);
      expect(find.byKey(const ValueKey('drive-row-did:ad:b')), findsNothing);

      // Tapping anywhere on the row (its value, not just the chevron).
      await tester.tap(find.text('4.0 MB · 2 drives'));
      await tester.pumpAndSettle();
      // Biggest drive first, with its size and count.
      final archive =
          tester.getTopLeft(find.byKey(const ValueKey('drive-row-did:ad:a')));
      final team =
          tester.getTopLeft(find.byKey(const ValueKey('drive-row-did:ad:b')));
      expect(archive.dy, lessThan(team.dy));
      expect(find.text('3.0 MB'), findsOneWidget);
      expect(find.text('1.5k resources'), findsOneWidget);
      expect(find.text('200 resources'), findsOneWidget);

      await tester.tap(find.text('4.0 MB · 2 drives'));
      await tester.pumpAndSettle();
      expect(find.byKey(const ValueKey('drive-row-did:ad:a')), findsNothing);
    });

    testWidgets('the expanded state is kept across a rebuild', (tester) async {
      await pumpScreen(tester, full());
      await showStorage(tester);
      await tester.tap(find.byKey(const Key('stats-total')));
      await tester.pumpAndSettle();
      expect(
          (await SharedPreferences.getInstance())
              .getBool('sync_storage_expanded'),
          true);

      await tester.pumpWidget(const SizedBox());
      await pumpScreen(tester, full());
      await showStorage(tester);
      expect(find.byKey(const ValueKey('drive-row-did:ad:a')), findsOneWidget);
    });

    testWidgets('a drive row opens that drive\'s storage page', (tester) async {
      final opened = <String>[];
      await pumpScreen(tester, full(), storagePage: (drive, title) {
        opened.add('$drive|$title');
        return Scaffold(body: Text('page $title'));
      });
      await showStorage(tester);
      await tester.tap(find.byKey(const Key('stats-total')));
      await tester.pumpAndSettle();
      await tester
          .ensureVisible(find.byKey(const ValueKey('drive-row-did:ad:b')));
      await tester.tap(find.byKey(const ValueKey('drive-row-did:ad:b')));
      await tester.pumpAndSettle();
      expect(opened, ['did:ad:b|Storage · Team']);
      expect(find.text('page Storage · Team'), findsOneWidget);
    });

    testWidgets('a spinner stands in while the data is counted',
        (tester) async {
      final done = Completer<shared.StoreStats?>();
      await tester.pumpWidget(_app(SyncScreen(
        backend: full()..stats = (() => done.future),
        loadAccount: (_) async => null,
      )));
      await tester.pump();
      await tester.pump();
      expect(find.byKey(const Key('stats-loading')), findsOneWidget);
      done.complete(stats);
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('stats-loading')), findsNothing);
      expect(find.byKey(const Key('stats-total')), findsOneWidget);
    });

    testWidgets('a count that fails shows nothing broken', (tester) async {
      await tester.pumpWidget(_app(SyncScreen(
        backend: full()..stats = (() async => throw StateError('no store')),
        loadAccount: (_) async => null,
      )));
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
      expect(find.byKey(const Key('stats-loading')), findsNothing);
      expect(find.byKey(const Key('stats-total')), findsNothing);
      expect(find.textContaining('no store'), findsNothing);
      expect(find.text('Pixel'), findsOneWidget);
    });

    testWidgets('the device id copies on tap', (tester) async {
      String? copied;
      tester.binding.defaultBinaryMessenger
          .setMockMethodCallHandler(SystemChannels.platform, (call) async {
        if (call.method == 'Clipboard.setData') {
          copied = (call.arguments as Map)['text'] as String?;
        }
        return null;
      });
      addTearDown(() => tester.binding.defaultBinaryMessenger
          .setMockMethodCallHandler(SystemChannels.platform, null));
      await tester.pumpWidget(_app(SyncScreen(
        backend: full(),
        loadAccount: (_) async => null,
      )));
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.byKey(const Key('copy-device-id')));
      await tester.tap(find.byKey(const Key('copy-device-id')));
      await tester.pump();
      expect(copied, 'a1b2c3d4e5f6a7b8c9d0e1f2');
      expect(find.text('Device ID copied'), findsOneWidget);
      await tester.pumpAndSettle(const Duration(seconds: 5));
    });
  });

  group('This device card alignment', () {
    setUp(() => SharedPreferences.setMockInitialValues({}));

    final stats = shared.StoreStats.fromJson({
      'resources': 3,
      'loro_bytes': 2048,
      'disk_bytes': 4096,
      'drives': [
        {
          'subject': 'did:ad:a',
          'name': 'Private',
          'resources': 3,
          'bytes': 2048
        },
      ],
    })!;

    for (final size in [const Size(393, 852), const Size(1200, 900)]) {
      for (final brightness in Brightness.values) {
        for (final scale in [1.0, 1.3]) {
          testWidgets(
              'one grid: ${size.width.toInt()} dp, ${brightness.name}, x$scale',
              (tester) async {
            tester.view.physicalSize = size;
            tester.view.devicePixelRatio = 1;
            addTearDown(tester.view.reset);
            final backend = _Backend()
              ..stats = (() async => stats)
              ..info = const shared.DeviceInfo(
                  platform: 'Android', appVersion: '0.41.0-a-very-long-build')
              ..peers = [
                {
                  'node_id': 'n1',
                  'name': 'Laptop',
                  'last_synced': '1700000000000'
                },
              ];
            await tester.pumpWidget(MaterialApp(
              theme: ThemeData(brightness: brightness, extensions: [
                brightness == Brightness.dark ? AppColors.dark : AppColors.light
              ]),
              builder: (context, child) => MediaQuery(
                  data: MediaQuery.of(context)
                      .copyWith(textScaler: TextScaler.linear(scale)),
                  child: child!),
              home:
                  SyncScreen(backend: backend, loadAccount: (_) async => null),
            ));
            await tester.pumpAndSettle();

            final card = find.ancestor(
                of: find.byKey(const Key('this-device-name')),
                matching: find.byType(SyncCard));
            await tester.ensureVisible(find.byKey(const Key('stats-disk')));
            await tester.pumpAndSettle();
            final cardRect = tester.getRect(card);
            final rows = find.descendant(
                of: card, matching: find.byKey(const Key('kv-row')));
            expect(rows, findsAtLeastNWidgets(6));

            final labelX = <double>{};
            final valueX = <double>{};
            final slotRight = <double>{};
            final singleLineHeights = <double>{};
            final baselineDiff = <double>[];
            for (final row in rows.evaluate()) {
              final f = find.byElementPredicate((e) => e == row);
              final rect = tester.getRect(f);
              expect(rect.height, greaterThanOrEqualTo(48));
              final label = find.descendant(
                  of: f, matching: find.byKey(const Key('kv-label')));
              final value = find.descendant(
                  of: f, matching: find.byKey(const Key('kv-value')));
              final slot = find.descendant(
                  of: f, matching: find.byKey(const Key('kv-slot')));
              labelX.add(tester.getTopLeft(label).dx);
              slotRight.add(tester.getRect(slot).right);
              if (value.evaluate().isNotEmpty) {
                valueX.add(tester.getTopLeft(value).dx);
                // Both text boxes are one line of the same row: their
                // vertical centres differ only by the font-size difference.
                baselineDiff.add((tester.getRect(label).bottom -
                        tester.getRect(value).bottom)
                    .abs());
              }
              if (find
                  .descendant(
                      of: f, matching: find.byKey(const Key('kv-subtitle')))
                  .evaluate()
                  .isEmpty) {
                singleLineHeights.add(rect.height);
              }
              // Everything stays inside the card's inner 16 dp.
              expect(rect.left, cardRect.left + 1);
            }
            expect(labelX.length, 1, reason: 'label x $labelX');
            // Value x differs from the label x by the same width for all rows.
            expect(valueX.length, 1, reason: 'value x $valueX');
            expect(slotRight.length, 1, reason: 'slot right $slotRight');
            expect(singleLineHeights.length, 1,
                reason: 'heights $singleLineHeights');
            expect(slotRight.single, closeTo(cardRect.right - 1 - 4, 0.5));
            // Label x is the 16 dp gutter + 24 icon + 12 gap from the card.
            expect(
                labelX.single - cardRect.left, closeTo(1 + 16 + 24 + 12, 0.5));
            // The header's text sits at the same x as the labels.
            final nameX = tester.getTopLeft(find.text('Pixel')).dx;
            expect(nameX, labelX.single);
            // Baselines: label (14 sp) and value (13 sp) bottoms are within a
            // pixel or two of each other once baseline-aligned.
            for (final d in baselineDiff) {
              expect(d, lessThan(3));
            }
          });
        }
      }
    }

    testWidgets('a long value ellipsises on one line, keeping the grid',
        (tester) async {
      tester.view.physicalSize = const Size(393, 852);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.reset);
      final backend = _Backend()
        ..stats = (() async => stats)
        ..info = shared.DeviceInfo(platform: 'Android', appVersion: 'v' * 80);
      await tester.pumpWidget(
          _app(SyncScreen(backend: backend, loadAccount: (_) async => null)));
      await tester.pumpAndSettle();
      final v = find.text('v' * 80);
      expect(tester.getSize(v).height, lessThan(24));
      final slot = tester.getRect(find.descendant(
          of: find.ancestor(of: v, matching: find.byKey(const Key('kv-row'))),
          matching: find.byKey(const Key('kv-slot'))));
      expect(tester.getRect(v).right, lessThanOrEqualTo(slot.left));
    });
  });

  group('style consistency', () {
    final allowedSizes = {12.0, 13.0, 14.0, 15.0, 20.0};

    Future<void> pumpFull(WidgetTester tester, Brightness brightness,
        {Size size = const Size(393, 852)}) async {
      tester.view.physicalSize = size;
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.reset);
      final backend = _Backend(servers: _Servers(managed: true))
        ..stats = (() async => shared.StoreStats.fromJson({
              'resources': 3,
              'loro_bytes': 2048,
              'drives': [
                {
                  'subject': 'did:ad:a',
                  'name': 'Private',
                  'resources': 3,
                  'bytes': 2048
                },
              ],
            }))
        ..info = const shared.DeviceInfo(platform: 'Android', appVersion: '1')
        ..peers = [
          {'node_id': 'n1', 'name': 'Laptop', 'last_synced': '1700000000000'},
        ];
      await tester.pumpWidget(MaterialApp(
        theme: ThemeData(brightness: brightness, extensions: [
          brightness == Brightness.dark ? AppColors.dark : AppColors.light
        ]),
        home: SyncScreen(
          backend: backend,
          loadCredits: () async => null,
          loadAccount: (_) async => AccountSummary(
            address: 'joep@example.org',
            portal: Uri.parse('https://portal.example'),
          ),
        ),
      ));
      await tester.pumpAndSettle();
    }

    for (final brightness in Brightness.values) {
      testWidgets('only the allowed font sizes, ${brightness.name}',
          (tester) async {
        await pumpFull(tester, brightness);
        final bad = <String>[];
        // Everything the list builds, scrolled through in pages.
        for (var page = 0; page < 8; page++) {
          for (final e in tester.widgetList<Text>(find.byType(Text))) {
            final text = e.data ?? e.textSpan?.toPlainText() ?? '';
            if (text.isEmpty) continue;
            final element = tester.element(find.byWidget(e).first);
            // The avatar's letter is a picture, not text.
            if (element.findAncestorWidgetOfExactType<ProfileAvatar>() !=
                null) {
              continue;
            }
            final size =
                DefaultTextStyle.of(element).style.merge(e.style).fontSize;
            // Buttons and app bar title come from the theme: judged by size.
            if (size != null && !allowedSizes.contains(size) && size != 22) {
              bad.add('$text: $size');
            }
          }
          await tester.drag(find.byType(ListView).first, const Offset(0, -400));
          await tester.pumpAndSettle();
        }
        expect(bad.toSet(), isEmpty);
      });
    }

    testWidgets('every card shares one border, radius and fill',
        (tester) async {
      await pumpFull(tester, Brightness.dark);
      final cards = <BoxDecoration>[];
      for (var page = 0; page < 8; page++) {
        for (final card in tester.widgetList<SyncCard>(find.byType(SyncCard))) {
          final c = tester.element(find.byWidget(card).first);
          final box = tester
              .widgetList<Container>(find.descendant(
                  of: find.byWidget(card), matching: find.byType(Container)))
              .map((w) => w.decoration)
              .whereType<BoxDecoration>()
              .first;
          expect(box, shared.syncCardDecoration(shared.syncColors(c)));
          cards.add(box);
        }
        await tester.drag(find.byType(ListView).first, const Offset(0, -400));
        await tester.pumpAndSettle();
      }
      expect(cards, isNotEmpty);
      final first = cards.first;
      for (final b in cards) {
        expect(b.border, first.border);
        expect(b.borderRadius, BorderRadius.circular(12));
        expect(b.color, first.color);
        expect(b.boxShadow, isNull);
      }
    });

    testWidgets('tablet: the column is centred and at most 720 wide',
        (tester) async {
      await pumpFull(tester, Brightness.light, size: const Size(1200, 900));
      final card = tester.getRect(find.byType(SyncCard).first);
      expect(card.width, lessThanOrEqualTo(720));
      expect(card.center.dx, closeTo(600, 1));
    });

    testWidgets('phone: cards keep 16 dp gutters', (tester) async {
      await pumpFull(tester, Brightness.light);
      final card = tester.getRect(find.byType(SyncCard).first);
      expect(card.left, 16);
      expect(card.right, 393 - 16);
    });
  });
}
