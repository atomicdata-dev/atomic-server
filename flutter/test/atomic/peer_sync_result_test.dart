import 'package:flutter_test/flutter_test.dart';
import 'package:atomic_app/atomic/atomic_client.dart';

/// A sync reported one number: what it imported. So sending a workspace to a
/// device that had none said "Synced 0 resources" under a green tick, and so
/// did two devices that already held the same thing. Both read as failure.
void main() {
  group('describe', () {
    test('sending a workspace says it was sent, not that nothing happened', () {
      const result = PeerSyncResult(imported: 0, pushed: 12, inSync: false);

      expect(result.describe(), 'Sent 12 resources');
    });

    test('already level says so, rather than counting to zero', () {
      const result = PeerSyncResult(imported: 0, pushed: 0, inSync: true);

      expect(result.describe(), 'Already in sync');
    });

    test('receiving says what came', () {
      const result = PeerSyncResult(imported: 3, pushed: 0, inSync: false);

      expect(result.describe(), 'Received 3 resources');
    });

    test('both directions say both', () {
      const result = PeerSyncResult(imported: 3, pushed: 12, inSync: false);

      expect(result.describe(), 'Synced — sent 12, received 3');
    });

    test('nothing at all, and not level: say that plainly', () {
      const result = PeerSyncResult(imported: 0, pushed: 0, inSync: false);

      expect(result.describe(), 'Nothing to sync');
    });

    test('names the device when it introduced itself', () {
      const result = PeerSyncResult(
        imported: 0,
        pushed: 12,
        inSync: false,
        peerName: 'Alice’s Laptop',
      );

      expect(result.describe(), 'Sent 12 resources with Alice’s Laptop');
    });

    test('falls back to a name the caller knows from an earlier HELLO', () {
      const result = PeerSyncResult(imported: 0, pushed: 0, inSync: true);

      expect(result.describe('Alice’s Laptop'),
          'Already in sync with Alice’s Laptop');
    });

    test('one resource is not "1 resources"', () {
      const sent = PeerSyncResult(imported: 0, pushed: 1, inSync: false);
      const got = PeerSyncResult(imported: 1, pushed: 0, inSync: false);

      expect(sent.describe(), 'Sent 1 resource');
      expect(got.describe(), 'Received 1 resource');
    });
  });

  group('fromJson', () {
    test('reads what the bridge sends', () {
      final result = PeerSyncResult.fromJson({
        'imported': 3,
        'pushed': 12,
        'in_sync': false,
        'peer_name': '24129PN74G',
      });

      expect(result.imported, 3);
      expect(result.pushed, 12);
      expect(result.inSync, isFalse);
      expect(result.peerName, '24129PN74G');
    });

    test('a report missing fields is empty, not a crash', () {
      final result = PeerSyncResult.fromJson({});

      expect(result.imported, 0);
      expect(result.pushed, 0);
      expect(result.inSync, isFalse);
      expect(result.peerName, isNull);
    });
  });

  test('counts say what moved, for under a "Paired with …" title', () {
    PeerSyncResult r(int i, int p, [bool s = false]) =>
        PeerSyncResult(imported: i, pushed: p, inSync: s);
    expect(r(7, 0).counts(), '7 resources received');
    expect(r(1, 0).counts(), '1 resource received');
    expect(r(0, 3).counts(), '3 resources sent');
    expect(r(7, 3).counts(), 'Received 7, sent 3');
    expect(r(0, 0, true).counts(), 'Already in sync');
    expect(r(0, 0).counts(), 'Nothing to sync');
  });
}
