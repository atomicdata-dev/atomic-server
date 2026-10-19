import 'package:atomic_flutter/atomic_flutter.dart' as shared;
import 'package:atomic_chat/atomic_chat.dart' show ResourceWebView;
import 'package:atomic_app/atomic/account_store.dart';
import 'package:atomic_app/screens/sync_screen.dart';
import 'package:atomic_app/theme.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

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

  _Backend({shared.AtomicServerBackend? servers}) : _servers = servers;

  @override
  Future<shared.AtomicIdentity?> getActiveAgent() async =>
      const shared.AtomicIdentity(subject: 'did:ad:agent', name: 'Joep');
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
  Future<List<Map<String, String>>> getKnownPeers() async => [];
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
    expect(find.text('Private'), findsOneWidget);
    expect(find.text('Team'), findsOneWidget);
    expect(find.text('Account'), findsNothing);
    expect(find.text('Link your account'), findsNothing);
  });

  testWidgets('a linked account shows address, vault and server',
      (tester) async {
    await tester.pumpWidget(_app(SyncScreen(
      backend: _Backend(servers: _Servers(managed: true)),
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
    await tester.scrollUntilVisible(find.text('Team'), 300);
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
      portalCookie: cookie,
      portalPage: (page) {
        opened = page;
        return const Scaffold(body: Text('portal page'));
      },
    )));
    await tester.pumpAndSettle();
    await tester.scrollUntilVisible(find.text('Manage in the portal'), 300);
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
    expect(asked, Uri.parse('https://portal.example'));
    expect(find.text('portal page'), findsOneWidget);
    expect(page!.cookies, hasLength(1));
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
}
