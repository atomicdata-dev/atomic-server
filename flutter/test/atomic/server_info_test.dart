import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:atomic_app/atomic/atomic_auth.dart';
import 'package:atomic_app/atomic/server_info.dart';

/// A secret in the shape `setup()` hands out: base64 of {privateKey, subject}.
String _secret(String privateKeyB64, String subject) => base64Encode(
      utf8.encode(jsonEncode({'privateKey': privateKeyB64, 'subject': subject})),
    );

void main() {
  group('ServerInfo.fromJsonAd', () {
    test('reads what a node says about itself', () {
      final info = ServerInfo.fromJsonAd({
        ServerProps.nodeId: 'did:ad:node:abc',
        ServerProps.version: '0.41.0-beta.0',
        ServerProps.managed: true,
        ServerProps.portalUrl: 'https://portal.example',
      });

      expect(info.nodeId, 'did:ad:node:abc');
      expect(info.version, '0.41.0-beta.0');
      expect(info.managed, isTrue);
      expect(info.portalUrl, 'https://portal.example');
    });

    test('a self-hosted node reports no portal and is not managed', () {
      final info = ServerInfo.fromJsonAd({
        ServerProps.version: '0.41.0-beta.0',
        ServerProps.managed: false,
      });

      expect(info.managed, isFalse);
      expect(info.portalUrl, isNull);
    });

    test('a node with no p2p transport has no node id, and that is not an error', () {
      final info = ServerInfo.fromJsonAd({ServerProps.version: '0.41.0-beta.0'});

      expect(info.nodeId, isNull);
      expect(info.version, '0.41.0-beta.0');
    });
  });

  group('signedHeaders', () {
    // Signing must match what atomic_lib's `get_authentication_headers` builds,
    // or the server rejects every request this client makes.
    final agent = AtomicAgent.fromSecret(
      _secret(base64Encode(List<int>.filled(32, 7)), 'did:ad:agent:test'),
    );

    test('sends the four headers the server checks', () {
      final headers = signedHeaders('http://localhost:9883/drive-usage', agent);

      expect(
        headers.keys.toSet(),
        {
          'x-atomic-public-key',
          'x-atomic-signature',
          'x-atomic-timestamp',
          'x-atomic-agent',
        },
      );
      expect(headers['x-atomic-agent'], 'did:ad:agent:test');
      expect(headers['x-atomic-public-key'], agent.publicKeyB64);
    });

    test('signs "<url> <timestamp>" — the message the server rebuilds', () {
      final headers = signedHeaders('http://localhost:9883/x', agent);
      final timestamp = headers['x-atomic-timestamp']!;
      final expected =
          signMessage('http://localhost:9883/x $timestamp', agent.privateKeyB64);

      expect(headers['x-atomic-signature'], expected);
    });

    test('a different url signs differently, so a signature cannot be reused', () {
      final a = signedHeaders('http://localhost:9883/a', agent);
      final b = signedHeaders('http://localhost:9883/b', agent);

      expect(a['x-atomic-signature'], isNot(b['x-atomic-signature']));
    });
  });

  group('formatBytes', () {
    test('reads the way a person reads sizes', () {
      expect(formatBytes(0), '0 B');
      expect(formatBytes(512), '512 B');
      expect(formatBytes(2048), '2.0 KB');
      expect(formatBytes(5 * 1024 * 1024), '5.0 MB');
      expect(formatBytes(20 * 1024 * 1024), '20 MB');
    });
  });
}
