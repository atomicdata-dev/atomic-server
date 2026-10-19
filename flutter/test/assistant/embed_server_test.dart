import 'dart:io';

import 'package:atomiccanvas_flutter/assistant/embed_server.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  // The test binding fakes every HTTP request; this one talks to a real server.
  setUpAll(() => HttpOverrides.global = null);

  Future<(int, String?)> get(EmbedServer server, String path) async {
    final client = HttpClient();
    try {
      final request = await client.getUrl(server.page.replace(path: path));
      final response = await request.close();
      await response.drain<void>();
      return (response.statusCode, response.headers.contentType?.mimeType);
    } finally {
      client.close(force: true);
    }
  }

  test('serves only its own files, on the loopback address', () async {
    final server = await EmbedServer.instance();
    expect(server.page.host, '127.0.0.1');
    expect(server.page.path, '/embed.html');
    // Starting again is the same server.
    expect(identical(await EmbedServer.instance(), server), isTrue);

    // A file of the bundle (the placeholder is always there).
    expect((await get(server, '/.gitkeep')).$1, 200);
    expect((await get(server, '/missing.js')).$1, 404);
    // Nothing outside the embed folder, however it is spelled.
    expect((await get(server, '/../pubspec.yaml')).$1, 404);
    expect((await get(server, '/%2e%2e/pubspec.yaml')).$1, 404);
    expect((await get(server, '/assets/../../pubspec.yaml')).$1, 404);
  });

  test('keeps the same port from one start to the next, if it is free',
      () async {
    final first = await EmbedServer.start(port: 0);
    final port = first.page.port;
    await first.close();
    final again = await EmbedServer.start(port: port);
    expect(again.page.port, port);
    // Taken: it moves to another port instead of failing.
    final other = await EmbedServer.start(port: port);
    expect(other.page.port, isNot(port));
    await again.close();
    await other.close();
  });
}
