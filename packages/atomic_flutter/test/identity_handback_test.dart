import 'dart:convert';
import 'dart:io';
import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

String _b64u(List<int> b) => base64Url.encode(b).replaceAll('=', '');

/// A real agent secret and its subject, shaped as the web app writes them.
Future<({String secret, String subject})> _agent(int fill) async {
  final seed = List<int>.filled(32, fill);
  final pub =
      (await (await Ed25519().newKeyPairFromSeed(seed)).extractPublicKey())
          .bytes;
  final subject = 'did:ad:agent:${_b64u(pub)}';
  final secret = base64.encode(
      utf8.encode(jsonEncode({'privateKey': _b64u(seed), 'subject': subject})));
  return (secret: secret, subject: subject);
}

void main() {
  final vector = jsonDecode(File('test/fixtures/identity_handback_vector.json')
      .readAsStringSync()) as Map<String, dynamic>;

  test('opens the vector the browser test also seals', () async {
    final app = await AtomicIdentityHandback.create(
        seed: AtomicIdentityHandback.decodeBase64Url(vector['app_private']));
    expect(app.appKey, vector['app_key']);
    final payload = await app.open(
        epk: vector['epk'],
        nonce: vector['nonce'],
        ciphertext: vector['ciphertext']);
    expect(payload, jsonDecode(vector['plaintext']));
  });

  test('sealing with the same fixed inputs reproduces the vector', () async {
    final sealed = await AtomicIdentityHandback.seal(
        vector['app_key'], jsonDecode(vector['plaintext']),
        senderSeed:
            AtomicIdentityHandback.decodeBase64Url(vector['sender_private']),
        nonce: AtomicIdentityHandback.decodeBase64Url(vector['nonce']));
    expect(sealed, {
      'epk': vector['epk'],
      'nonce': vector['nonce'],
      'ciphertext': vector['ciphertext'],
    });
  });

  test('refuses tampering and a different app key', () async {
    final app = await AtomicIdentityHandback.create(
        seed: AtomicIdentityHandback.decodeBase64Url(vector['app_private']));
    final bytes = AtomicIdentityHandback.decodeBase64Url(vector['ciphertext']);
    bytes[3] ^= 1;
    await expectLater(
        app.open(
            epk: vector['epk'],
            nonce: vector['nonce'],
            ciphertext: _b64u(bytes)),
        throwsStateError);
    final other = await AtomicIdentityHandback.create();
    await expectLater(
        other.open(
            epk: vector['epk'],
            nonce: vector['nonce'],
            ciphertext: vector['ciphertext']),
        throwsStateError);
  });

  test('a secret must derive the public key its subject names', () async {
    final a = await _agent(7), b = await _agent(9);
    expect(
        await AtomicIdentityHandback.secretMatchesSubject(a.secret, a.subject),
        isTrue);
    expect(
        await AtomicIdentityHandback.secretMatchesSubject(a.secret, b.subject),
        isFalse);
    expect(await AtomicIdentityHandback.secretMatchesSubject('junk', a.subject),
        isFalse);
  });

  group('client', () {
    Future<AtomicAccountClient> clientFor(
        {required String subjectInPayload,
        required String secret,
        bool sealedAnswer = true,
        List<Map<String, dynamic>>? requests}) async {
      String? appKey;
      return AtomicAccountClient('https://portal.example',
          client: MockClient((request) async {
        if (request.method == 'POST' &&
            request.url.path == '/api/device-link') {
          final body = jsonDecode(request.body) as Map<String, dynamic>;
          requests?.add(body);
          appKey = body['app_key'] as String?;
          return http.Response(
              jsonEncode({
                'device_code': 'dc',
                'user_code': 'ABCD-1234',
                'expires_in': 300,
                'interval': 2
              }),
              200);
        }
        if (request.url.path == '/api/device-link/dc') {
          return http.Response(
              jsonEncode({
                'state': 'approved',
                'token': 'tok',
                if (sealedAnswer)
                  'sealed_identity': await AtomicIdentityHandback.seal(
                      appKey!, {
                    'secret': secret,
                    'subject': subjectInPayload,
                    'drive': 'did:ad:drive'
                  }),
              }),
              200);
        }
        if (request.url.path == '/api/me') {
          return http.Response('{"email":"e","address":"me@example"}', 200);
        }
        return http.Response('no', 404);
      }));
    }

    test('sends app_key and opens the sealed identity once', () async {
      final agent = await _agent(7);
      final requests = <Map<String, dynamic>>[];
      final client = await clientFor(
          subjectInPayload: agent.subject,
          secret: agent.secret,
          requests: requests);
      final link = await client.requestLink('Phone', handback: true);
      expect(link.wantsIdentity, isTrue);
      expect(requests.single['app_key'], isA<String>());
      expect(
          AtomicIdentityHandback.decodeBase64Url(requests.single['app_key'])
              .length,
          32);
      expect(await client.pollLink(link), AtomicLinkProgress.approved);
      final identity = client.takeHandedBackIdentity()!;
      expect(identity.secret, agent.secret);
      expect(identity.subject, agent.subject);
      expect(identity.drive, 'did:ad:drive');
      expect(identity.address, 'me@example');
      expect(client.takeHandedBackIdentity(), isNull);
      expect(
          link
              .sendIdentityUrl(AtomicAccountClient.appOrigin(client.origin))
              .toString(),
          'https://app.portal.example/app/send-identity?code=ABCD-1234');
    });

    test('a plain link sends no key and an older portal gives no identity',
        () async {
      final requests = <Map<String, dynamic>>[];
      final client = await clientFor(
          subjectInPayload: '',
          secret: '',
          sealedAnswer: false,
          requests: requests);
      final link = await client.requestLink('Phone');
      expect(requests.single.containsKey('app_key'), isFalse);
      expect(link.wantsIdentity, isFalse);
      await client.pollLink(link);
      expect(client.takeHandedBackIdentity(), isNull);

      final asking = await clientFor(
          subjectInPayload: '', secret: '', sealedAnswer: false);
      final handback = await asking.requestLink('Phone', handback: true);
      await asking.pollLink(handback);
      expect(asking.takeHandedBackIdentity(), isNull);
    });

    test('an identity that does not match its subject is refused', () async {
      final a = await _agent(7), b = await _agent(9);
      final client =
          await clientFor(subjectInPayload: b.subject, secret: a.secret);
      final link = await client.requestLink('Phone', handback: true);
      await expectLater(client.pollLink(link), throwsStateError);
      expect(client.takeHandedBackIdentity(), isNull);
    });

    test('appOrigin puts the web app before the portal host', () {
      expect(AtomicAccountClient.appOrigin(Uri.parse('https://atomic.place')),
          Uri.parse('https://app.atomic.place'));
      expect(
          AtomicAccountClient.appOrigin(Uri.parse('https://app.atomic.place')),
          Uri.parse('https://app.atomic.place'));
    });
  });
}
