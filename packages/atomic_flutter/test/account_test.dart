import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:atomic_flutter/atomic_flutter.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  final fixture =
      jsonDecode(File('test/fixtures/account-envelope.json').readAsStringSync())
          as Map<String, dynamic>;
  final envelope = fixture['envelope'] as Map<String, dynamic>;
  test('decrypts browser-compatible AES-GCM and rejects tampering', () async {
    final wrapper =
        (envelope['wrappers'] as List).single as Map<String, dynamic>;
    expect(
        await AtomicAccountClient.openAssistedEnvelope(
            envelope, wrapper, fixture['key']),
        'synthetic-atomic-secret');
    final corrupt = base64Decode(envelope['encrypted_secret'] as String)
      ..[0] ^= 1;
    await expectLater(
        AtomicAccountClient.openAssistedEnvelope(
            {...envelope, 'encrypted_secret': base64Encode(corrupt)},
            wrapper,
            fixture['key']),
        throwsStateError);
  });
  test('link, recover and discover without exposing tokens to other origins',
      () async {
    final calls = <String>[];
    final client = AtomicAccountClient('https://provider.example',
        client: MockClient((request) async {
      expect(request.url.origin, 'https://provider.example');
      expect(request.followRedirects, isFalse);
      calls.add(request.url.path);
      if (request.url.path.startsWith('/api/device-link')) {
        expect(request.headers.containsKey('Authorization'), isFalse);
      } else {
        expect(request.headers['Authorization'], 'Bearer private-test-token');
      }
      switch (request.url.path) {
        case '/api/device-link':
          return http.Response(
              jsonEncode({
                'device_code': 'device-secret',
                'user_code': 'ABCD-EFGH',
                'expires_in': 300,
                'interval': 2
              }),
              200);
        case '/api/device-link/device-secret':
          return http.Response(
              '{"state":"approved","token":"private-test-token"}', 200);
        case '/api/me':
          return http.Response(
              '{"email":"acct_test","address":"person@example.invalid"}', 200);
        case '/api/recovery-secret':
          return http.Response(jsonEncode(envelope), 200);
        case '/api/recovery-secret/assisted-key':
          return http.Response(jsonEncode({'key': fixture['key']}), 200);
        case '/api/devices':
          return http.Response('{"devices":[]}', 200);
        case '/api/sync-enrollments':
          return http.Response('[]', 200);
      }
      throw StateError('Unexpected request');
    }));
    final link = await client.requestLink('Audio Mac');
    expect(link.approvalUrl.toString(),
        'https://provider.example/link?code=ABCD-EFGH');
    expect(link.approvalUrl.toString(), isNot(contains('device-secret')));
    expect(await client.pollLink(link), AtomicLinkProgress.approved);
    expect((await client.recoverIdentity()).secret, 'synthetic-atomic-secret');
    expect(await client.devices(), isEmpty);
    expect(await client.enrollments(), isEmpty);
    expect(
        () => AtomicAccountClient('https://other.example')
            .restoreSession(client.exportSession()),
        throwsStateError);
    expect(calls, hasLength(7));
    client.close();
  });
  test(
      'rejects unsafe origins, redirects, missing backups and account mismatch',
      () async {
    for (final url in [
      'http://provider.example',
      'https://user:pass@provider.example',
      'https://provider.example/path',
      'https://provider.example?query=secret'
    ]) {
      expect(() => AtomicAccountClient(url), throwsArgumentError);
    }
    final client = AtomicAccountClient('https://provider.example',
        client: MockClient((r) async => http.Response('', 302,
            headers: {'location': 'https://other.example'})));
    await expectLater(client.requestLink('test'), throwsStateError);
    final mismatch = AtomicAccountClient('https://provider.example',
        client: MockClient((r) async => http.Response(
            jsonEncode(r.url.path == '/api/me'
                ? {'email': 'another-account'}
                : envelope),
            200)))
      ..restoreSession('{"origin":"https://provider.example","token":"test"}');
    await expectLater(mismatch.recoverIdentity(), throwsStateError);
    client.close();
    mismatch.close();
  });
  test('expired links and malformed replies never produce a linked session',
      () async {
    final client = AtomicAccountClient('https://provider.example',
        client: MockClient((r) async => http.Response('', 404)));
    final link = AtomicDeviceLink.fromJson({
      'device_code': 'private',
      'user_code': 'PUBLIC',
      'expires_in': 300,
      'interval': 120
    }, Uri.parse('https://provider.example'));
    expect(link.interval, const Duration(seconds: 120));
    expect(await client.pollLink(link), AtomicLinkProgress.expired);
    expect(client.linked, isFalse);
    final broken = AtomicAccountClient('https://provider.example',
        client: MockClient(
            (r) async => http.Response('secret response malformed', 200)));
    try {
      await broken.requestLink('test');
      fail('must reject malformed response');
    } catch (error) {
      expect(error.toString(), isNot(contains('secret response')));
    }
    client.close();
    broken.close();
  });

  testWidgets('closing approval dialog never installs a late response',
      (tester) async {
    final response = Completer<http.Response>();
    var installed = false;
    final client = AtomicAccountClient('https://provider.example',
        client: MockClient((r) => response.future));
    await tester.pumpWidget(MaterialApp(
        home: AtomicAccountLinkDialog(
            client: client,
            deviceName: 'test',
            openUrl: (_) async {},
            install: (identity, session) async {
              installed = true;
            })));
    await tester.pumpWidget(const SizedBox());
    response.complete(http.Response(
        '{"device_code":"private","user_code":"PUBLIC","expires_in":300,"interval":1}',
        200));
    await tester.pump(const Duration(seconds: 3));
    expect(installed, isFalse);
    expect(tester.takeException(), isNull);
    client.close();
  });
  group('agent sign-in', () {
    Future<String> fakeSign(String m) async => 'sig:$m';
    MockClient portal(int status, List<http.Request> seen) =>
        MockClient((request) async {
          seen.add(request);
          switch (request.url.path) {
            case '/api/auth/agent/challenge':
              return http.Response(
                jsonEncode({'nonce': 'n1', 'challenge': 'chal'}),
                200,
              );
            case '/api/auth/agent':
              return status == 204
                  ? http.Response(
                      '',
                      204,
                      headers: {
                        'set-cookie':
                            'session_token=abc123; Path=/; HttpOnly; Secure',
                      },
                    )
                  : http.Response(jsonEncode({'signed_in': false}), status);
            default:
              return http.Response(jsonEncode({'enabled': true}), 200);
          }
        });

    test('204 makes a cookie session that is sent on later requests', () async {
      final seen = <http.Request>[];
      final client = AtomicAccountClient(
        'https://provider.example',
        client: portal(204, seen),
      );
      expect(await client.signInWithAgent('did:ad:agent:x', fakeSign), isTrue);
      expect(client.linked, isTrue);
      expect(client.sessionCookie, 'abc123');
      final body = jsonDecode(seen[1].body) as Map;
      expect(seen[1].url.query, 'if_linked=true');
      expect(body['nonce'], 'n1');
      expect(body['signature'], 'sig:chal ${body['timestamp']}');
      await client.aiStatus();
      expect(seen.last.headers['Cookie'], 'session_token=abc123');
      expect(seen.last.headers.containsKey('Authorization'), isFalse);
      expect(seen.last.headers['Origin'], 'https://provider.example');
      final restored = AtomicAccountClient('https://provider.example')
        ..restoreSession(client.exportSession());
      expect(restored.linked, isTrue);
    });

    test('200 signed_in:false leaves the client signed out', () async {
      final seen = <http.Request>[];
      final client = AtomicAccountClient(
        'https://provider.example',
        client: portal(200, seen),
      );
      expect(await client.signInWithAgent('did:ad:agent:x', fakeSign), isFalse);
      expect(client.linked, isFalse);
      expect(client.sessionCookie, isNull);
      await expectLater(client.aiStatus(), throwsStateError);
    });
  });

  group('AI credits', () {
    AtomicAccountClient linked(
            int status, Object body, List<http.Request> seen) =>
        AtomicAccountClient('https://provider.example',
            client: MockClient((request) async {
          seen.add(request);
          return http.Response(jsonEncode(body), status);
        }))
          ..restoreSession(jsonEncode(
              {'origin': 'https://provider.example/', 'token': 't'}));

    test('reads ai/status in whole credits', () async {
      final seen = <http.Request>[];
      final credits = await linked(
              200,
              {
                'enabled': true,
                'allowance_micros': 10000,
                'remaining_micros': 7500,
                'purchased_remaining_micros': 2000,
                'purchases_enabled': true,
                'resets_at': 1800000000,
              },
              seen)
          .aiCredits();
      expect(seen.single.url.path, '/api/ai/status');
      expect(seen.single.headers['Authorization'], 'Bearer t');
      expect(credits!.remaining, 7);
      expect(credits.allowance, 10);
      expect(credits.purchased, 2);
      expect(credits.purchasesEnabled, isTrue);
      expect(credits.resetsAt!.millisecondsSinceEpoch, 1800000000000);
    });

    test('null when AI is off, missing or the session is invalid', () async {
      expect(await linked(200, {'enabled': false}, []).aiCredits(), isNull);
      expect(await linked(404, {}, []).aiCredits(), isNull);
      expect(await linked(401, {}, []).aiCredits(), isNull);
    });

    test('a server error throws so callers keep the last known value',
        () async {
      await expectLater(linked(500, {}, []).aiCredits(), throwsStateError);
    });
  });

  test('portalDrivesUrl targets the portal Drives page in embed mode', () {
    expect(
        AtomicAccountClient.portalDrivesUrl(Uri.parse('https://atomic.place/'))
            .toString(),
        'https://atomic.place/dashboard/drives?embed=1');
    expect(
        () => AtomicAccountClient.portalDrivesUrl(Uri.parse('http://x.test')),
        throwsArgumentError);
  });
}
