import 'dart:convert';
import 'dart:io';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

/// The host app's bundle, with one file of the renderer in it.
class _Bundle extends CachingAssetBundle {
  final Map<String, String> files;
  _Bundle(this.files);

  @override
  Future<ByteData> load(String key) async {
    final text = files[key];
    if (text == null) throw StateError('no asset $key');
    return ByteData.sublistView(utf8.encode(text));
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  // The test binding fakes every HTTP request; this one talks to a real server.
  setUpAll(() => HttpOverrides.global = null);
  setUp(() {
    EmbedServer.bundle = _Bundle({
      'assets/embed/embed.html': '<html></html>',
      'assets/embed/assets/index-abc.js': '',
      'pubspec.yaml': 'secret',
    });
  });
  tearDown(() {
    EmbedServer.bundle = rootBundle;
    EmbedServer.assetRoot = 'assets/embed';
  });

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

    // The files of the bundle, under the asset root.
    expect(await get(server, '/'), (200, 'text/html'));
    expect(await get(server, '/assets/index-abc.js'), (200, 'text/javascript'));
    expect((await get(server, '/missing.js')).$1, 404);
    // Nothing outside the embed folder, however it is spelled.
    expect((await get(server, '/../pubspec.yaml')).$1, 404);
    expect((await get(server, '/%2e%2e/pubspec.yaml')).$1, 404);
    expect((await get(server, '/assets/../../pubspec.yaml')).$1, 404);
  });

  test('reads from the asset root the host set', () async {
    EmbedServer.bundle = _Bundle({'web/renderer/embed.html': '<html></html>'});
    EmbedServer.assetRoot = 'web/renderer';
    final server = await EmbedServer.start(port: 0);
    expect((await get(server, '/embed.html')).$1, 200);
    expect((await get(server, '/missing.js')).$1, 404);
    await server.close();
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
