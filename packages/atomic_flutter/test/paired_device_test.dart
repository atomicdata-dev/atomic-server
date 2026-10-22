import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

const _me = 'did:ad:agent:joep';
const _polle = 'did:ad:agent:polle';

class _Backend extends AtomicSettingsBackend {
  _Backend(this.peers, {this.live = const {}, this.sync});
  final List<Map<String, String>> peers;
  final Set<String> live;
  final Future<String> Function(String nodeId)? sync;
  final removed = <String>[];

  @override
  Future<String> Function(String nodeId)? get syncPeer => sync;
  @override
  Future<AtomicIdentity?> getActiveAgent() async =>
      const AtomicIdentity(subject: _me);
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
  Future<Set<String>> livePeerIds() async => live;
  @override
  Future<void> removeKnownPeer(String nodeId) async {
    removed.add(nodeId);
    peers.removeWhere((p) => p['node_id'] == nodeId);
  }

  @override
  Future<void> pair(BuildContext context) async {}
}

Future<void> _pump(WidgetTester tester, _Backend backend) async {
  await tester.pumpWidget(MaterialApp(
    home: Scaffold(
      body: SingleChildScrollView(
        child: ServerSettingsSection(backend: backend),
      ),
    ),
  ));
  await tester.pumpAndSettle();
}

final _polleId = 'ab' * 32;

Map<String, String> _pollesPhone({Map<String, String> extra = const {}}) => {
      'node_id': _polleId,
      'name': 'iPhone',
      'last_synced': '${DateTime.now().millisecondsSinceEpoch}',
      'agent': _polle,
      'agent_name': 'Polle Smit',
      'last_received': '0',
      'last_sent': '3',
      'drives': '1',
      ...extra,
    };

void main() {
  group('PairedDevice.fromRow', () {
    test('a row from an older host reads as before', () {
      final d = PairedDevice.fromRow(
          {'node_id': 'cd' * 32, 'name': 'Mac', 'last_synced': ''},
          ownAgent: _me);
      expect(d.relation, PeerRelation.unknown);
      expect(d.relationLabel, isNull);
      expect(d.label, 'Mac');
      expect(d.lastSynced, isNull);
      expect(d.lastSyncCounts, isNull);
    });

    test('another agent is someone else\'s device', () {
      final d = PairedDevice.fromRow(_pollesPhone(), ownAgent: _me);
      expect(d.relation, PeerRelation.contact);
      expect(d.relationLabel, 'Shared with you');
      expect(d.label, 'Polle Smit · iPhone');
      expect(d.initials, 'PS');
      expect(d.lastSyncCounts, 'received 0, sent 3');
    });

    test('my own agent is my device; an explicit relation wins', () {
      final mine = PairedDevice.fromRow(
          {'node_id': 'ef' * 32, 'name': 'Pixel', 'agent': _me},
          ownAgent: _me);
      expect(mine.relation, PeerRelation.sameAgent);
      expect(mine.relationLabel, 'Your device');

      final replica = PairedDevice.fromRow(
          {'node_id': 'ef' * 32, 'agent': _polle, 'relation': 'replica'},
          ownAgent: _me);
      expect(replica.relation, PeerRelation.replica);
    });
  });

  testWidgets('a paired person shows with their name, avatar and status',
      (tester) async {
    await _pump(tester, _Backend([_pollesPhone()], live: {_polleId}));

    expect(find.text('Polle Smit · iPhone'), findsOneWidget);
    expect(find.byKey(const ValueKey('peer-person-avatar')), findsOneWidget);
    expect(find.text('PS'), findsOneWidget);
    expect(find.text('Shared with you'), findsOneWidget);
    expect(find.text('Connected'), findsOneWidget);
    expect(find.textContaining('Last synced just now'), findsOneWidget);
  });

  testWidgets('my own device says so and keeps its device icon',
      (tester) async {
    await _pump(
        tester,
        _Backend([
          {'node_id': 'ef' * 32, 'name': 'Pixel', 'agent': _me},
        ]));

    expect(find.text('Pixel'), findsOneWidget);
    expect(find.text('Your device'), findsOneWidget);
    expect(find.byIcon(Icons.phone_android), findsOneWidget);
    expect(find.text('Paired'), findsOneWidget);
  });

  testWidgets('the details sheet copies the id, syncs, and forgets',
      (tester) async {
    final synced = <String>[];
    final backend = _Backend([_pollesPhone()], sync: (node) async {
      synced.add(node);
      return 'Received 2 resources from iPhone';
    });
    await _pump(tester, backend);

    await tester.tap(find.byKey(ValueKey('peer-card-$_polleId')));
    await tester.pumpAndSettle();

    expect(find.text('Offline'), findsOneWidget);
    expect(find.text('Signed in as'), findsOneWidget);
    expect(find.text('Polle Smit'), findsOneWidget);
    expect(find.text('Device ID'), findsWidgets);
    expect(find.text('received 0, sent 3'), findsOneWidget);
    expect(find.textContaining("Someone else's device"), findsOneWidget);

    await tester.ensureVisible(find.text('Sync now'));
    await tester.tap(find.text('Sync now'));
    await tester.pumpAndSettle();
    expect(synced, [_polleId]);
    expect(find.text('Received 2 resources from iPhone'), findsOneWidget);

    await tester.ensureVisible(find.text('Forget this device'));
    await tester.tap(find.text('Forget this device'));
    await tester.pumpAndSettle();
    expect(backend.removed, [_polleId]);
    expect(find.text('Polle Smit · iPhone'), findsNothing);
  });

  testWidgets('a failed sync says why; no sync hook, no button',
      (tester) async {
    await _pump(
        tester,
        _Backend([_pollesPhone()],
            sync: (_) async => throw Exception('Iroh connect timed out')));
    await tester.tap(find.byKey(ValueKey('peer-card-$_polleId')));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.text('Sync now'));
    await tester.tap(find.text('Sync now'));
    await tester.pumpAndSettle();
    expect(find.textContaining('timed out'), findsOneWidget);

    await tester.pumpWidget(const SizedBox());
    await _pump(tester, _Backend([_pollesPhone()]));
    await tester.tap(find.byKey(ValueKey('peer-card-$_polleId')));
    await tester.pumpAndSettle();
    expect(find.text('Sync now'), findsNothing);
    expect(find.text('Forget this device'), findsOneWidget);
  });
}
