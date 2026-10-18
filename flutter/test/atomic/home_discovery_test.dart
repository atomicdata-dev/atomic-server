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

  group('connectKnownServer', () {
    test('connects to the known server that serves the drive and uses it',
        () async {
      String? connected, active;
      final origin = await AtomicClient.connectKnownServer(
        drive,
        activeServer: () async => null,
        knownServers: () async =>
            ['https://other.example', 'https://home.example'],
        setActiveServer: (o) async => active = o,
        client: MockClient((request) async => request.url.host == 'home.example'
            ? http.Response('{"ok":1}', 200)
            : http.Response('no', 404)),
        verifies: (body, _) => body.contains('ok'),
        connect: (o) async => connected = o,
      );
      expect(origin, 'https://home.example');
      expect(connected, 'https://home.example');
      expect(active, 'https://home.example');
    });

    test('two lookups at once connect once', () async {
      var connects = 0;
      Future<String?> look() => AtomicClient.connectKnownServer(
            drive,
            activeServer: () async => null,
            knownServers: () async => ['https://home.example'],
            setActiveServer: (_) async {},
            client: MockClient((_) async => http.Response('{}', 200)),
            verifies: (_, __) => true,
            connect: (_) async {
              connects++;
              await Future<void>.delayed(const Duration(milliseconds: 20));
            },
          );
      final results = await Future.wait([look(), look()]);
      expect(results, ['https://home.example', 'https://home.example']);
      expect(connects, 1);
    });

    test('leaves a server in use alone', () async {
      var asked = false;
      final origin = await AtomicClient.connectKnownServer(
        drive,
        activeServer: () async => 'https://in-use.example',
        knownServers: () async {
          asked = true;
          return ['https://home.example'];
        },
      );
      expect(origin, isNull);
      expect(asked, isFalse);
    });

    test('no known server, nothing to connect', () async {
      expect(
        await AtomicClient.connectKnownServer(
          drive,
          activeServer: () async => null,
          knownServers: () async => [],
        ),
        isNull,
      );
    });
  });
}
