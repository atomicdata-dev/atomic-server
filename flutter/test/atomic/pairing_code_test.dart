import 'package:flutter_test/flutter_test.dart';
import 'package:atomiccanvas_flutter/screens/pair_screen.dart';

/// The node id in the code the data-browser showed for its server.
const _hex =
    '959866605fedfbc79d3890579d587410bfb05329f48cfe5186297ac8cf51888f';

void main() {
  group('atomic:pair codes (what the data-browser and Tauri apps show)', () {
    test('still reads the older double-slash form', () {
      final peer = PairScreen.parsePeerInfo(
        'atomic://pair?v=1&node=did:ad:node:$_hex&drives=*',
      );
      expect(peer, isNotNull);
      expect(peer!.nodeId, _hex);
    });

    test('reads the code a browser shows for the server its drives live on', () {
      // Copied from the Sync page, verbatim.
      final peer = PairScreen.parsePeerInfo(
        'atomic:pair?v=1&node=did:ad:node:$_hex&drives=*',
      );

      expect(peer, isNotNull);
      expect(peer!.nodeId, _hex);
      expect(peer.drives, isNull, reason: '"*" means every drive, not a filter');
    });

    test('keeps the server the code advertises', () {
      final peer = PairScreen.parsePeerInfo(
        'atomic://pair?v=1&node=did:ad:node:$_hex&url=https%3A%2F%2Fmy.server.com&drives=*',
      );

      expect(peer!.serverUrl, 'https://my.server.com');
    });

    test('a code that names a drive says which one — that is what unsticks a new device', () {
      // A device holding only a secret has no drive to sync. The code naming
      // one is the whole mechanism for its first pull; `*` names none.
      final peer = PairScreen.parsePeerInfo(
        'atomic://pair?v=1&node=did:ad:node:$_hex&drives=did%3Aad%3Amyworkspace',
      );

      expect(peer!.drives, ['did:ad:myworkspace']);
    });

    test('reads every drive when a code names more than one', () {
      final peer = PairScreen.parsePeerInfo(
        'atomic://pair?v=1&node=did:ad:node:$_hex&drives=did%3Aad%3Aone&drives=did%3Aad%3Atwo',
      );

      expect(peer!.drives, ['did:ad:one', 'did:ad:two']);
    });

    test('refuses a newer version rather than half-reading it', () {
      final peer = PairScreen.parsePeerInfo(
        'atomic://pair?v=2&node=did:ad:node:$_hex&drives=*',
      );

      expect(peer, isNull);
    });

    test('refuses a code with no node, or a malformed one', () {
      expect(PairScreen.parsePeerInfo('atomic://pair?v=1&drives=*'), isNull);
      expect(
        PairScreen.parsePeerInfo('atomic://pair?v=1&node=did:ad:node:nothex'),
        isNull,
      );
      expect(
        PairScreen.parsePeerInfo('atomic://pair?v=1&node=$_hex'),
        isNull,
        reason: 'the node must be a node DID, not a bare hex string',
      );
    });
  });

  group('this app’s own codes still work', () {
    test('a node DID, with and without a device name', () {
      expect(PairScreen.parsePeerInfo('did:ad:node:$_hex')!.nodeId, _hex);

      final named = PairScreen.parsePeerInfo(
        PairScreen.formatQrValue(_hex, 'Alice’s Laptop'),
      );
      expect(named!.nodeId, _hex);
      expect(named.name, 'Alice’s Laptop');
    });

    test('raw hex and iroh: prefixes, as pasted by hand', () {
      expect(PairScreen.parsePeerInfo(_hex)!.nodeId, _hex);
      expect(PairScreen.parsePeerInfo('iroh:$_hex')!.nodeId, _hex);
      expect(PairScreen.parsePeerInfo('  $_hex  ')!.nodeId, _hex);
    });

    test('nonsense is not a pairing code', () {
      expect(PairScreen.parsePeerInfo(''), isNull);
      expect(PairScreen.parsePeerInfo('https://example.com'), isNull);
      expect(PairScreen.parsePeerInfo('did:ad:node:tooshort'), isNull);
    });
  });
}
