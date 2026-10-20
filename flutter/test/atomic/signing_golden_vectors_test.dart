import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:atomic_app/atomic/atomic_auth.dart';

/// The same fixture the Rust side asserts (`lib/src/genesis.rs::matches_the_golden_vectors`)
/// and the TS side asserts (`browser/lib/src/genesis.test.ts`). Dart signs
/// requests with its own ed25519 code, so without this it could only ever agree
/// with itself — and a signature the server rejects looks like a network fault,
/// not a wrong alphabet.
///
/// This asserts the crypto layer only (sign these bytes with this key, get this
/// string). Building a genesis cert in Dart is not needed to know that Dart and
/// Rust sign and encode identically.
void main() {
  final fixtureFile = File.fromUri(
    Directory.current.uri.resolve('../lib/src/genesis_test_vectors.json'),
  );

  test('fixture is where the Rust and TS suites read it from', () {
    expect(
      fixtureFile.existsSync(),
      isTrue,
      reason: 'expected the shared vectors at ${fixtureFile.path}',
    );
  });

  final fixture =
      jsonDecode(fixtureFile.readAsStringSync()) as Map<String, dynamic>;
  final vectors = (fixture['vectors'] as List).cast<Map<String, dynamic>>();

  test('signs the golden vectors exactly as Rust does', () {
    expect(vectors, isNotEmpty);

    for (final vector in vectors) {
      final certBytes = _hexToBytes(vector['certBytesHex'] as String);
      final signature = signBytes(certBytes, vector['privateKeyBase64'] as String);

      expect(
        signature,
        vector['signature'],
        reason: 'vector seedByte=${vector['seedByte']} must sign identically',
      );
    }
  });

  test('derives the same public key from the same secret', () {
    for (final vector in vectors) {
      final secret = base64Encode(utf8.encode(jsonEncode({
        'privateKey': vector['privateKeyBase64'],
        'subject': vector['signerDid'],
      })));

      final agent = AtomicAgent.fromSecret(secret);

      expect(
        _bytesToHex(decodeAtomicBase64(agent.publicKeyB64)),
        vector['pubKeyHex'],
        reason: 'vector seedByte=${vector['seedByte']} public key must match',
      );
    }
  });

  group('base64', () {
    test('writes URL-safe and unpadded, the way keys travel in DIDs', () {
      final encoded = encodeAtomicBase64(List<int>.filled(32, 251));

      expect(encoded, isNot(contains('+')));
      expect(encoded, isNot(contains('/')));
      expect(encoded, isNot(contains('=')));
    });

    test('reads either alphabet, padded or not', () {
      final bytes = List<int>.generate(32, (i) => i * 7 % 256);
      final urlSafe = encodeAtomicBase64(bytes);
      final standardPadded = base64Encode(bytes);

      expect(decodeAtomicBase64(urlSafe), Uint8List.fromList(bytes));
      expect(decodeAtomicBase64(standardPadded), Uint8List.fromList(bytes));
    });
  });
}

Uint8List _hexToBytes(String hex) {
  final bytes = Uint8List(hex.length ~/ 2);

  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }

  return bytes;
}

String _bytesToHex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
