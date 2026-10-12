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
}
