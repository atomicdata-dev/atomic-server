import 'dart:convert';

import 'package:atomic_store/atomic_store.dart';
import 'package:atomic_store/testing.dart';
import 'package:atomic_store_flutter/atomic_store_flutter.dart';
import 'package:atomic_store_flutter/bridge/api/node.dart' as bridge;
import 'package:atomic_store_flutter/testing.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:flutter_test/flutter_test.dart';

final _a = 'a1' * 32;
final _b = 'b2' * 32;

Store _store() {
  final backend = InMemoryBackend();
  return Store(backend: backend);
}

void main() {
  group('mapping the bridge rows', () {
    test('known peers: dates, live flag, most recently synced first', () {
      final peers = knownPeersFromBridge([
        bridge.KnownPeerInfo(nodeId: _a, name: 'Old'),
        bridge.KnownPeerInfo(
            nodeId: _b,
            name: 'Laptop',
            lastSynced: 1700000000000,
            lastSent: 3,
            lastReceived: 4),
      ], {
        _a
      });
      expect(peers.map((p) => p.nodeId), [_b, _a]);
      expect(peers.first.lastSynced,
          DateTime.fromMillisecondsSinceEpoch(1700000000000));
      expect(peers.first.lastReceived, 4);
      expect(peers.first.live, isFalse);
      expect(peers.last.live, isTrue);
      expect(peers.last.lastSynced, isNull);
    });

    test('drives and sync results', () {
      final drives = drivesFromBridge([
        const bridge.DriveSummary(
            subject: 'did:ad:1',
            name: 'Home',
            emoji: '🏠',
            unreadable: false,
            active: true),
      ]);
      expect(
          drives.single,
          const DriveInfo(
              subject: 'did:ad:1', name: 'Home', emoji: '🏠', active: true));
      final r = peerSyncResultFromBridge(const bridge.PeerSyncOutcome(
          imported: 2, pushed: 1, inSync: false, peerName: 'Phone'));
      expect(
          [r.imported, r.pushed, r.inSync, r.peerName], [2, 1, false, 'Phone']);
    });

    test('peer events and the search status come from the bridge JSON', () {
      final e = PeerEvent.fromJson({
        'remote_node_id': _a,
        'resources_imported': 5,
        'timestamp': 1700000000000,
        'kind': 'connected',
      })!;
      expect([e.nodeId, e.kind, e.resourcesImported], [_a, 'connected', 5]);
      expect(PeerEvent.fromJson('x'), isNull);
      final s = PeerSearchStatus.fromJson(
          '{"state":"searching","message":"Looking"}');
      expect([s.state, s.message], ['searching', 'Looking']);
      expect(PeerSearchStatus.fromJson('nope').state, '');
    });
  });

  group('FakePeers', () {
    test('pairing parses the code, syncs, and remembers the device', () async {
      final peers = FakePeers(deviceName: 'Phone');
      expect(peers.pairingCode, isNull);
      await peers.start();
      expect(PairingCode.parse(peers.pairingCode!)!.name, 'Phone');

      peers.reachable.add(_a);
      final names = <List<String>>[];
      final sub = peers
          .watchKnown()
          .listen((l) => names.add([for (final p in l) p.name]));
      await peers.pair(PairingCode.format(_a, 'Laptop'));
      await Future<void>.delayed(Duration.zero);
      expect(peers.known.single.name, 'Laptop');
      expect(peers.known.single.lastSynced, isNotNull);
      expect(names.last, ['Laptop']);

      await expectLater(peers.pair('nonsense'), throwsFormatException);
      await expectLater(
          peers.pair(PairingCode.format(_b)), throwsA(isA<StoreException>()));
      expect(peers.known, hasLength(1),
          reason: 'a device that did not answer is not paired');
      await sub.cancel();
    });

    test('live devices and syncing everything', () async {
      final peers = FakePeers();
      peers.reachable.add(_a);
      peers.add(_a, 'Laptop');
      peers.add(_b, 'Gone');
      peers.connect(_a);
      expect(peers.known.firstWhere((p) => p.nodeId == _a).live, isTrue);
      final result = await peers.syncNow();
      expect(result.answered, 1);
      expect(result.failures, hasLength(1));
      peers.rename(_b, 'Old tablet');
      expect(peers.known.firstWhere((p) => p.nodeId == _b).name, 'Old tablet');
      peers.remove(_b);
      peers.disconnect(_a);
      expect(peers.liveIds, isEmpty);
    });
  });

  group('FakeServerSync, FakeDrives, FakeIdentity', () {
    test('resume reports ready, offline or needs sync', () async {
      final sync = FakeServerSync(hasDrive: false)
        ..servers.add('https://s.example');
      expect(
          await sync.resume('https://nowhere.example'), ResumeStatus.offline);
      expect(await sync.resume('https://s.example'), ResumeStatus.needsSync);
      expect(sync.status.connected, isTrue);
      sync.hasDrive = true;
      expect(await sync.resume(null), ResumeStatus.ready);
      await sync.disconnect();
      expect(sync.status.connected, isFalse);
      expect(sync.status.origin, 'https://s.example');
    });

    test('creating or switching a drive moves the store', () async {
      final store = _store();
      final drives = FakeDrives(store);
      final changes = <String?>[];
      final sub = drives.watchCurrent().listen(changes.add);
      await Future<void>.delayed(Duration.zero);
      final home = await drives.create('Home');
      final work = await drives.create('Work');
      expect(store.drive, work.subject);
      await drives.switchTo(home.subject);
      await Future<void>.delayed(Duration.zero);
      expect(store.drive, home.subject);
      expect(changes, [null, home.subject, work.subject, home.subject]);
      expect((await drives.list()).first.subject, home.subject);
      await sub.cancel();
    });

    test('identity: create, sign out, sign in', () async {
      final store = _store();
      final id = FakeIdentity(store);
      final made = await id.create('Alice');
      expect(store.drive, made.drive);
      await id.updateProfile(name: 'Alice B', description: 'hi');
      expect((await id.profile()).name, 'Alice B');
      await id.signOut();
      expect(id.secret, isNull);
      id.known['other'] = (drive: 'did:ad:other', needsSync: true);
      final found = await id.signIn('other');
      expect(found.needsSync, isTrue);
      expect(store.drive, 'did:ad:other');
      await expectLater(id.signIn('bad'), throwsA(isA<StoreException>()));
    });

    test('signing in as someone else brings the work along, once', () async {
      final id = FakeIdentity(_store());
      final made = await id.create('Alice');
      id.work = ['did:ad:notes', 'did:ad:shared'];
      id.known['bob'] = (drive: 'did:ad:bob', needsSync: false);

      final first = await id.signIn('bob');
      expect(first.broughtAlong, ['did:ad:notes', 'did:ad:shared']);
      expect(first.previousSecret, made.secret);

      final again = await id.signIn('bob');
      expect(again.broughtAlong, isEmpty);
      expect(again.previousSecret, isNull);
    });
  });

  group('Sharing', () {
    const folder = 'did:ad:test:folder';
    Future<(Store, Sharing, List<String>)> setup() async {
      final backend = InMemoryBackend({
        folder: {Props.name: const StringValue('Shared')},
      });
      final store = Store(backend: backend);
      final signed = <String>[];
      final sharing = Sharing(store, (target, write, exp, max) {
        signed.add('$target $write $exp $max');
        return 'tok+en/=';
      });
      return (store, sharing, signed);
    }

    test('grant, change and revoke an agent', () async {
      final (store, sharing, _) = await setup();
      expect(await sharing.rights(folder), isEmpty);
      await sharing.grant(folder, 'did:ad:agent:bob', ShareRole.read);
      await sharing.grant(folder, 'did:ad:agent:eve', ShareRole.write);
      expect(await sharing.rights(folder), [
        const Access('did:ad:agent:eve', ShareRole.write),
        const Access('did:ad:agent:bob', ShareRole.read),
      ]);
      final raw = await store.getResource(folder, fresh: true);
      expect(raw.getLinks(Props.read),
          containsAll(['did:ad:agent:bob', 'did:ad:agent:eve']),
          reason: 'writers are listed as readers too');

      await sharing.grant(folder, 'did:ad:agent:bob', ShareRole.write);
      await sharing.revoke(folder, 'did:ad:agent:eve');
      expect(await sharing.rights(folder),
          [const Access('did:ad:agent:bob', ShareRole.write)]);
      await sharing.revoke(folder, 'did:ad:agent:bob');
      final empty = await store.getResource(folder, fresh: true);
      expect(empty.get(Props.read), isNull);
      expect(empty.get(Props.write), isNull);
    });

    test('public access is the public agent in the lists', () async {
      final (_, sharing, _) = await setup();
      expect(await sharing.publicAccess(folder), isNull);
      await sharing.setPublic(folder, ShareRole.read);
      expect(await sharing.publicAccess(folder), ShareRole.read);
      expect((await sharing.rights(folder)).single.isPublic, isTrue);
      await sharing.setPublic(folder, ShareRole.write);
      expect(await sharing.publicAccess(folder), ShareRole.write);
      await sharing.setPublic(folder, null);
      expect(await sharing.rights(folder), isEmpty);
    });

    test('an invite link carries the signed token, URL-encoded', () async {
      final (_, sharing, signed) = await setup();
      final link = sharing.inviteLink('https://my.server/', folder,
          role: ShareRole.write, maxUsages: 5);
      expect(link, 'https://my.server/app/invite?token=tok%2Ben%2F%3D');
      expect(signed.single, '$folder true null 5');
      expect(() => sharing.inviteToken(folder, maxUsages: 0),
          throwsA(isA<StoreException>()));
    });
  });

  group('serverless invite links', () {
    Sharing sharing({InviteAcceptor? accept}) => Sharing(
        Store(backend: InMemoryBackend(), drive: 'did:ad:test:home'),
        (t, w, e, m) => 'tok+en/=',
        acceptor: accept);

    test('without a server origin the link names no server', () {
      final link = sharing().inviteLink(null, 'did:ad:test:home');
      expect(link, 'atomic:invite?token=tok%2Ben%2F%3D');
      final parsed = Sharing.parseInvite(link)!;
      expect(parsed.token, 'tok+en/=');
      expect(parsed.serverOrigin, isNull);
    });

    test('a server link, a bare token and rubbish are told apart', () {
      final server = Sharing.parseInvite(
          'https://my.server/app/invite?token=tok%2Ben%2F%3D')!;
      expect((server.token, server.serverOrigin),
          ('tok+en/=', 'https://my.server'));
      final bare = Sharing.parseInvite('  ${'A' * 40}== ')!;
      expect(bare.token, '${'A' * 40}==');
      expect(Sharing.parseInvite(''), isNull);
      expect(Sharing.parseInvite('hello there'), isNull);
      expect(Sharing.parseInvite('atomic:invite'), isNull);
      expect(
          Sharing.parseInvite('https://my.server/app/other?token=x'), isNull);
    });

    test('acceptInvite hands the token, not the link, to the node', () async {
      final seen = <String>[];
      final s = sharing(accept: (token) async {
        seen.add(token);
        return const AcceptedInvite(drive: 'did:ad:test:shared', write: false);
      });
      expect(s.canAccept, isTrue);
      final joined = await s.acceptInvite('atomic:invite?token=tok%2Ben%2F%3D');
      expect(seen, ['tok+en/=']);
      expect(joined.drive, 'did:ad:test:shared');
      await expectLater(
          s.acceptInvite('not a link'),
          throwsA(isA<StoreException>().having(
              (e) => e.message, 'message', contains('not an invite link'))));
    });

    test('without a node that can accept, it says so', () async {
      expect(sharing().canAccept, isFalse);
      await expectLater(sharing().acceptInvite('atomic:invite?token=abc'),
          throwsA(isA<StoreException>()));
    });

    test('a failed server link points at its server', () async {
      final s = sharing(
          accept: (_) async => throw const StoreException(
              StoreErrorKind.network,
              'The device that made this invite is offline.'));
      await expectLater(
          s.acceptInvite('https://my.server/app/invite?token=abc'),
          throwsA(isA<StoreException>().having((e) => e.message, 'message',
              endsWith('You can also open this link at https://my.server.'))));
    });
  });

  group('HomeServerDiscovery', () {
    HomeServerDiscovery discovery(Map<String, int> status,
            {List<String>? names}) =>
        HomeServerDiscovery(
          resolve: (_) async => status.keys.toList(),
          verifies: (body, drive) => body == 'genesis of $drive',
          client: MockClient((request) async {
            final origin = '${request.url.scheme}://${request.url.host}';
            expect(request.url.path, '/genesis');
            final code = status[origin] ?? 404;
            return http.Response(
                code == 200
                    ? 'genesis of ${request.url.queryParameters['subject']}'
                    : 'no',
                code);
          }),
        );

    test('connects to the first origin whose genesis verifies', () async {
      final d =
          discovery({'https://dead.example': 500, 'https://ok.example': 200});
      final connected = <String>[];
      final found = await d.discover('did:ad:drive',
          connect: (o) async => connected.add(o));
      expect(found, 'https://ok.example');
      expect(connected, ['https://ok.example']);
      expect(d.log.any((l) => l.contains('HTTP 500')), isTrue);
    });

    test('nothing verifies: null, and the log says why', () async {
      final d = discovery({'https://dead.example': 500});
      expect(await d.discover('did:ad:drive', connect: (_) async => fail('no')),
          isNull);
      expect(d.log.single, 'https://dead.example: HTTP 500');
      expect(await d.verifiedOrigins('did:ad:drive'), isEmpty);
    });

    test('verifiedOrigins keeps every origin that proves it', () async {
      final d = discovery({
        'https://a.example': 200,
        'https://b.example': 404,
        'https://c.example': 200
      });
      expect(await d.verifiedOrigins('did:ad:drive'),
          ['https://a.example', 'https://c.example']);
    });

    test('a failing connect is logged and rethrown', () async {
      final d = discovery({'https://ok.example': 200});
      await expectLater(
          d.discover('did:ad:drive',
              connect: (_) async => throw Exception('refused')),
          throwsException);
      expect(d.log.last, contains('refused'));
      jsonEncode(d.log);
    });
  });
}
