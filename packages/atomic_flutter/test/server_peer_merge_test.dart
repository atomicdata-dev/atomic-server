import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

class _Servers extends AtomicServerBackend {
  @override
  Future<List<String>> knownServers() async => ['https://node1.example.org'];
  @override
  Future<String?> activeServer() async => null;
  @override
  Future<ServerInfo> serverInfo(String url) async => ServerInfo.unknown;
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
  _Backend(this.peers);
  final List<Map<String, String>> peers;

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
  AtomicServerBackend? get servers => _Servers();
}

Future<void> _pump(WidgetTester tester, List<Map<String, String>> peers) async {
  await tester.pumpWidget(MaterialApp(
    home: Scaffold(
      body: SingleChildScrollView(
        child: ServerSettingsSection(backend: _Backend(peers)),
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
}
