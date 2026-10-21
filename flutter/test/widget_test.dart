import 'package:atomic_app/screens/pair_screen.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('PairScreen peer URI parsing', () {
    const nodeId =
        '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    test('parses atomic node URI with encoded name', () {
      final peer = PairScreen.parsePeerInfo(
        'atomic:node:$nodeId:Joe%27s%20Tablet',
      );

      expect(peer, isNotNull);
      expect(peer!.nodeId, nodeId);
      expect(peer.name, "Joe's Tablet");
    });

    test('parses did node URI with encoded name', () {
      final peer = PairScreen.parsePeerInfo(
        'did:ad:node:$nodeId:Joe%27s%20Tablet',
      );

      expect(peer, isNotNull);
      expect(peer!.nodeId, nodeId);
      expect(peer.name, "Joe's Tablet");
    });

    test('parses raw node id', () {
      final peer = PairScreen.parsePeerInfo(nodeId);

      expect(peer, isNotNull);
      expect(peer!.nodeId, nodeId);
      expect(peer.name, isEmpty);
    });

    test('rejects invalid input', () {
      expect(PairScreen.parsePeerInfo('did:ad:node:not-a-node'), isNull);
    });
  });
}
