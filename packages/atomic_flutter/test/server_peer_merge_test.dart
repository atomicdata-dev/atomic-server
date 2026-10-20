import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

class _Servers extends AtomicServerBackend {
  _Servers({
    List<String>? servers,
    this.infos = const {},
    this.discovered = const [],
  }) : servers = servers ?? ['https://node1.example.org'];
  final List<String> servers;
  final Map<String, ServerInfo> infos;
  final List<String> discovered;

  @override
  Future<List<String>> knownServers() async => servers;
  @override
  Future<String?> activeServer() async => null;
  @override
  Future<ServerInfo> serverInfo(String url) async =>
      infos[url] ?? ServerInfo.unknown;
  @override
  Future<List<String>> discoverServers() async {
    for (final url in discovered) {
      if (!servers.contains(url)) servers.add(url);
    }
    return discovered;
  }

  @override
  Future<DriveUsage?> driveUsage(String url) async => null;
  @override
  Future<void> switchTo(String url) async {}
  @override
  Future<void> add(String url) async {}
  @override
  Future<void> remove(String url) async {}
  @override
  Future<int> pushWorkspace(String url) async => 0;
}

class _Backend extends AtomicSettingsBackend {
  _Backend(this.peers, {_Servers? servers, this.search})
      : _servers = servers ?? _Servers();
  final List<Map<String, String>> peers;
  final _Servers _servers;
  PeerSearchInfo? search;
  int searches = 0;

  @override
  PeerSearchInfo? peerSearchStatus() => search;
  @override
  void Function()? get searchAgain => search == null ? null : () => searches++;

  @override
  Future<AtomicIdentity?> getActiveAgent() async => null;
  @override
  Future<String> exportSecret() async => '';
  @override
  Future<List<String>> listDrives() async => [];
  @override
  String? getActiveDrive() => null;
  @override
  Future<String> getDriveName(String drive) async => '';
  @override
  Future<void> createDrive(String name) async {}
  @override
  Future<void> switchDrive(String drive) async {}
  @override
  Future<String?> getPeerId() async => null;
  @override
  Future<String> getDeviceName() async => '';
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
  AtomicServerBackend? get servers => _servers;
}

Future<void> _pump(WidgetTester tester, List<Map<String, String>> peers,
    {_Backend? backend}) async {
  await tester.pumpWidget(MaterialApp(
    home: Scaffold(
      body: SingleChildScrollView(
        child: ServerSettingsSection(backend: backend ?? _Backend(peers)),
      ),
    ),
  ));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('a paired device that is a listed server is shown once',
      (tester) async {
    final now = DateTime.now().millisecondsSinceEpoch;
    await _pump(tester, [
      {
        'node_id': 'aa' * 32,
        'name': 'atomic.place (node1.example.org)',
        'last_synced': '$now',
      },
    ]);

    expect(find.text('node1.example.org'), findsOneWidget);
    expect(find.textContaining('atomic.place (node1'), findsNothing);
    expect(find.textContaining('Paired · last synced'), findsOneWidget);
  });

  testWidgets('another paired device stays listed', (tester) async {
    await _pump(tester, [
      {'node_id': 'bb' * 32, 'name': 'Mac.home', 'last_synced': ''},
    ]);

    expect(find.text('node1.example.org'), findsOneWidget);
    expect(find.text('Mac.home'), findsOneWidget);
  });

  testWidgets('a paired device hides its raw id behind a Copy ID button',
      (tester) async {
    final id = 'bb' * 32;
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
    await _pump(tester, [
      {'node_id': id, 'name': 'Mac.home', 'last_synced': ''},
    ]);

    expect(find.text(id), findsNothing);
    expect(find.text('Not synced yet'), findsOneWidget);
    await tester.tap(find.text('Copy ID'));
    await tester.pump();
    expect(copied, id);
    expect(find.text('ID copied'), findsOneWidget);
  });

  testWidgets('a server that names itself by its first label is that server',
      (tester) async {
    await _pump(
        tester,
        [
          {'node_id': 'cc' * 32, 'name': 'staging', 'last_synced': ''},
        ],
        backend: _Backend([
          {'node_id': 'cc' * 32, 'name': 'staging', 'last_synced': ''},
        ], servers: _Servers(servers: ['https://staging.atomicdata.dev'])));

    expect(find.text('staging.atomicdata.dev'), findsOneWidget);
    expect(find.text('https://staging.atomicdata.dev'), findsOneWidget);
    expect(find.byIcon(Icons.phone_android), findsNothing);
    expect(find.text('staging'), findsNothing);
  });

  testWidgets('a peer whose node id a listed server reports is that server',
      (tester) async {
    final id = 'dd' * 32;
    final peers = [
      {'node_id': id, 'name': 'node', 'last_synced': ''},
    ];
    await _pump(tester, peers,
        backend: _Backend(peers,
            servers: _Servers(
              servers: ['https://node1.atomicserver.eu'],
              infos: {
                'https://node1.atomicserver.eu':
                    ServerInfo(nodeId: id, version: '1'),
              },
            )));

    expect(find.byIcon(Icons.phone_android), findsNothing);
    expect(find.text('https://node1.atomicserver.eu'), findsOneWidget);
    expect(find.text('Copy ID'), findsOneWidget);
  });

  testWidgets('an atomic-server whose address is unknown is not a phone',
      (tester) async {
    await _pump(tester, [
      {
        'node_id': 'ee' * 32,
        'name': '896f7bd5-atomic-server',
        'last_synced': '',
        'relay_url': 'https://euw1-1.relay.iroh.network./',
      },
    ]);

    expect(find.byIcon(Icons.phone_android), findsNothing);
    expect(find.byIcon(Icons.cloud_outlined), findsWidgets);
    expect(find.textContaining('Server, address unknown'), findsOneWidget);
    expect(
        find.textContaining('via euw1-1.relay.iroh.network'), findsOneWidget);
  });

  testWidgets('servers the drive record names join the list', (tester) async {
    await _pump(tester, [],
        backend: _Backend([],
            servers: _Servers(
                servers: ['https://staging.atomicdata.dev'],
                discovered: ['https://node1.atomicserver.eu'])));

    expect(find.text('node1.atomicserver.eu'), findsOneWidget);
    expect(find.text('staging.atomicdata.dev'), findsOneWidget);
  });

  testWidgets('the device search says what it does, and can search again',
      (tester) async {
    final backend = _Backend([],
        search: const PeerSearchInfo(
          state: 'no_peers_yet',
          message: 'No other device found yet',
          detail: 'No other device has announced this workspace yet.',
          retryInSecs: 10,
        ));
    await _pump(tester, [], backend: backend);

    expect(find.text('No other device found yet · trying again in 10 s'),
        findsOneWidget);
    expect(find.textContaining('has announced'), findsNothing);
    await tester.tap(find.textContaining('No other device found yet'));
    await tester.pump();
    expect(find.textContaining('has announced'), findsOneWidget);

    await tester.tap(find.text('Search again'));
    await tester.pump();
    expect(backend.searches, 1);

    backend.search = const PeerSearchInfo(
        state: 'searching', message: 'Looking for devices…');
    await tester.pump(const Duration(seconds: 2));
    expect(find.text('Looking for devices…'), findsOneWidget);
    expect(find.text('Search again'), findsNothing);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('a failed search shows why at once', (tester) async {
    await _pump(tester, [],
        backend: _Backend([],
            search: const PeerSearchInfo(
              state: 'failed',
              message:
                  "Can't look for devices: the device directory could not be reached",
              detail:
                  'pkarr relay https://dns.iroh.link/pkarr unreachable: dns error',
              retryInSecs: 15,
            )));
    expect(find.textContaining('dns error'), findsOneWidget);
    await tester.pumpWidget(const SizedBox());
  });
}
