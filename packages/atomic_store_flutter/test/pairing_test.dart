import 'package:atomic_store_flutter/atomic_store_flutter.dart';
import 'package:flutter_test/flutter_test.dart';

const _hex = '959866605fedfbc79d3890579d587410bfb05329f48cfe5186297ac8cf51888f';

void main() {
  group('atomic://pair codes (what the web and desktop apps show)', () {
    test('reads a code with every drive', () {
      final code = PairingCode.parse(
          'atomic://pair?v=1&node=did:ad:node:$_hex&drives=*');
      expect(code!.nodeId, _hex);
      expect(code.drives, isNull, reason: '"*" means every drive');
    });

    test('keeps the advertised server and the drives it names', () {
      final code = PairingCode.parse(
          'atomic://pair?v=1&node=did:ad:node:$_hex&url=https%3A%2F%2Fmy.server.com&drives=did%3Aad%3Aone&drives=did%3Aad%3Atwo');
      expect(code!.serverUrl, 'https://my.server.com');
      expect(code.drives, ['did:ad:one', 'did:ad:two']);
    });

    test('refuses a newer version, a missing node and a bare hex node', () {
      expect(PairingCode.parse('atomic://pair?v=2&node=did:ad:node:$_hex'),
          isNull);
      expect(PairingCode.parse('atomic://pair?v=1&drives=*'), isNull);
      expect(PairingCode.parse('atomic://pair?v=1&node=did:ad:node:nothex'),
          isNull);
      expect(PairingCode.parse('atomic://pair?v=1&node=$_hex'), isNull);
    });
  });

  group('the codes of this package', () {
    test('format and parse round trip, with and without a device name', () {
      expect(PairingCode.format(_hex), 'atomic:node:$_hex');
      expect(PairingCode.parse(PairingCode.format(_hex))!.nodeId, _hex);
      final named =
          PairingCode.parse(PairingCode.format(_hex, 'Alice’s Laptop'));
      expect(named!.nodeId, _hex);
      expect(named.name, 'Alice’s Laptop');
    });

    test('older spellings, raw hex and iroh: as pasted by hand', () {
      expect(PairingCode.parse('did:ad:node:$_hex')!.nodeId, _hex);
      expect(PairingCode.parse('did:ad:node:$_hex:Phone')!.name, 'Phone');
      expect(PairingCode.parse('  $_hex  ')!.nodeId, _hex);
      expect(PairingCode.parse('iroh:$_hex')!.nodeId, _hex);
      expect(PairingCode.parse(_hex.toUpperCase())!.nodeId, _hex);
    });

    test('a node code can carry a server and drives; never a secret', () {
      final code = PairingCode.parse(
          'atomic:node:$_hex?v=1&url=https%3A%2F%2Fa.example&drives=*');
      expect(code!.serverUrl, 'https://a.example');
      expect(code.drives, isNull);
      expect(PairingCode.parse('atomic:node:$_hex?secret=x'), isNull);
      expect(PairingCode.parse('atomic:node:$_hex?v=9'), isNull);
    });

    test('anything else is not a code', () {
      expect(PairingCode.parse(''), isNull);
      expect(PairingCode.parse('hello'), isNull);
      expect(PairingCode.parse('did:ad:node:short'), isNull);
      expect(PairingCode.parse('https://example.com'), isNull);
    });
  });
}
