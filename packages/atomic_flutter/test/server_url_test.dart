import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('normalizeServerUrl', () {
    test('does not make people type a scheme', () {
      expect(normalizeServerUrl('localhost:9883'), 'http://localhost:9883');
      expect(normalizeServerUrl('127.0.0.1:9883'), 'http://127.0.0.1:9883');
    });

    test('assumes https off the local machine', () {
      expect(normalizeServerUrl('my.server.com'), 'https://my.server.com');
    });

    test('a LAN address is a dev server — the only one a phone can reach', () {
      // `localhost` means nothing on a phone; this is how it reaches a laptop.
      expect(normalizeServerUrl('192.168.0.79:9883'), 'http://192.168.0.79:9883');
      expect(normalizeServerUrl('10.0.0.5:9883'), 'http://10.0.0.5:9883');
      expect(normalizeServerUrl('172.16.4.2:9883'), 'http://172.16.4.2:9883');
      expect(normalizeServerUrl('mac.local:9883'), 'http://mac.local:9883');
    });

    test('a public address is still https, private-looking or not', () {
      expect(normalizeServerUrl('172.32.0.1:9883'), 'https://172.32.0.1:9883');
      expect(normalizeServerUrl('8.8.8.8'), 'https://8.8.8.8');
      expect(normalizeServerUrl('192.169.0.1'), 'https://192.169.0.1');
    });

    test('keeps an explicit scheme, including http on a remote host', () {
      expect(normalizeServerUrl('http://my.server.com'), 'http://my.server.com');
      expect(normalizeServerUrl('https://my.server.com'), 'https://my.server.com');
    });

    test('trims whitespace and trailing slashes, so one server is one entry', () {
      expect(normalizeServerUrl('  localhost:9883/  '), 'http://localhost:9883');
      expect(normalizeServerUrl('https://my.server.com///'), 'https://my.server.com');
    });

    test('empty stays empty — no server is a valid choice here', () {
      expect(normalizeServerUrl(''), '');
      expect(normalizeServerUrl('   '), '');
    });
  });

  group('sameOrigin', () {
    test('ignores trailing slashes and paths', () {
      expect(sameOrigin('http://localhost:9883', 'http://localhost:9883/'), isTrue);
      expect(sameOrigin('http://localhost:9883', 'http://localhost:9883/some/path'), isTrue);
    });

    test('a different port is a different server', () {
      expect(sameOrigin('http://localhost:9883', 'http://localhost:9884'), isFalse);
    });

    test('a different scheme is a different server', () {
      expect(sameOrigin('http://my.server.com', 'https://my.server.com'), isFalse);
    });

    test('no server is never the same as some server', () {
      expect(sameOrigin('http://localhost:9883', null), isFalse);
      expect(sameOrigin('http://localhost:9883', ''), isFalse);
    });
  });

  group('serverLabel', () {
    test('keeps the port, which is what tells two dev servers apart', () {
      expect(serverLabel('http://localhost:9883'), 'localhost:9883');
      expect(serverLabel('http://localhost:6747'), 'localhost:6747');
    });

    test('drops the scheme and the default port', () {
      expect(serverLabel('https://my.server.com'), 'my.server.com');
    });
  });
}
