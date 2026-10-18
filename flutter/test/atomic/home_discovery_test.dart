import 'package:atomiccanvas_flutter/atomic/atomic_client.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  const drive = 'atomic:abc';

  test('connects to the first origin whose genesis verifies', () async {
    final asked = <Uri>[];
    String? connected;
    final client = MockClient((request) async {
      asked.add(request.url);
      return switch (request.url.host) {
        'impostor.example' => http.Response('{"wrong":true}', 200),
        'dead.example' => http.Response('no', 404),
        _ => http.Response('{"genesis":"ok"}', 200),
      };
    });

    final origin = await AtomicClient.discoverHomeServer(
      drive,
      client: client,
      resolve: (_) async => [
        'https://impostor.example',
        'https://dead.example',
        'https://home.example',
      ],
      verifies: (body, d) => body.contains('"ok"') && d == drive,
      connect: (o) async => connected = o,
    );

    expect(origin, 'https://home.example');
    expect(connected, 'https://home.example');
    expect(asked.map((u) => u.host),
        containsAll(['impostor.example', 'dead.example', 'home.example']));
    expect(asked.first.path, '/genesis');
    expect(asked.first.queryParameters['subject'], drive);
  });

  test('a certificate that does not verify is never connected to', () async {
    var connected = false;
    final origin = await AtomicClient.discoverHomeServer(
      drive,
      client: MockClient((_) async => http.Response('{}', 200)),
      resolve: (_) async => ['https://a.example', 'https://b.example'],
      verifies: (_, __) => false,
      connect: (_) async => connected = true,
    );
    expect(origin, isNull);
    expect(connected, isFalse);
  });

  test('one origin that never answers does not stall the others', () async {
    final origin = await AtomicClient.discoverHomeServer(
      drive,
      client: MockClient((request) async {
        if (request.url.host == 'hung.example') {
          await Future<void>.delayed(const Duration(seconds: 30));
        }
        return http.Response('{}', 200);
      }),
      resolve: (_) async => ['https://hung.example', 'https://home.example'],
      verifies: (_, __) => true,
      connect: (_) async {},
      timeout: const Duration(milliseconds: 200),
    );
    expect(origin, 'https://home.example');
  });

  test('no announced origin means no server', () async {
    expect(
      await AtomicClient.discoverHomeServer(drive, resolve: (_) async => []),
      isNull,
    );
  });
}
