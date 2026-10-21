import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Serves the embedded renderer's own files ([assetRoot], `assets/embed/` by
/// default) to the app's web view, on the loopback address. A web view cannot run the renderer's modules
/// from `file://`, and this keeps the page on a real origin.
///
/// Only static files, read from the app's bundle: no data goes through it. The
/// page reaches the store through the app's JavaScript channel, not through
/// here.
class EmbedServer {
  EmbedServer._(this._server);

  static Future<EmbedServer>? _running;

  final HttpServer _server;

  /// Where the renderer's files are in [bundle]: the host app declares them
  /// as assets (the atomic.place app builds them with
  /// `flutter/scripts/build_embed.sh` into its own `assets/embed/`). Set
  /// before the first [instance].
  static String assetRoot = 'assets/embed';

  /// The bundle the files are read from; the app's own by default.
  static AssetBundle bundle = rootBundle;

  /// One server for the app's life; started the first time it is asked for.
  static Future<EmbedServer> instance() => _running ??= _start();

  /// The same port on every start, so the page keeps one origin and what it
  /// keeps in its own storage (its settings, the theme, the last used drive)
  /// is still there next time. A random port was a new origin on each launch,
  /// which looked like settings that did not stick.
  static const preferredPort = 47831;

  static Future<EmbedServer> _start() => start(port: preferredPort);

  /// Binds [port], or any free port when that one is taken.
  @visibleForTesting
  static Future<EmbedServer> start({required int port}) async {
    HttpServer server;
    try {
      server = await HttpServer.bind(InternetAddress.loopbackIPv4, port);
    } on SocketException {
      server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    }
    final embed = EmbedServer._(server);
    unawaited(embed._serve());
    return embed;
  }

  /// Where the page is: `http://127.0.0.1:<port>/embed.html`.
  Uri get page => Uri(
        scheme: 'http',
        host: _server.address.address,
        port: _server.port,
        path: '/embed.html',
      );

  Future<void> _serve() async {
    await for (final request in _server) {
      unawaited(_answer(request));
    }
  }

  Future<void> _answer(HttpRequest request) async {
    final path = request.uri.path == '/' ? '/embed.html' : request.uri.path;
    final bytes = await _read(path);
    final response = request.response;
    if (request.method != 'GET' || bytes == null) {
      response.statusCode = HttpStatus.notFound;
    } else {
      response.headers
        ..contentType = ContentType.parse(_type(path))
        // Built files carry a hash in their name.
        ..set(
            'Cache-Control',
            path.startsWith('/assets/')
                ? 'max-age=31536000, immutable'
                : 'no-cache');
      response.add(bytes);
    }
    await response.close();
  }

  /// A file of the bundle, or null. Only paths inside [assetRoot].
  static Future<Uint8List?> _read(String path) async {
    if (path.contains('..') || path.contains('\\')) return null;
    try {
      final data = await bundle.load('$assetRoot$path');
      return data.buffer.asUint8List(data.offsetInBytes, data.lengthInBytes);
    } catch (_) {
      return null;
    }
  }

  static String _type(String path) {
    final ext = path.split('.').last;
    return switch (ext) {
      'html' => 'text/html; charset=utf-8',
      'js' || 'mjs' => 'text/javascript; charset=utf-8',
      'css' => 'text/css; charset=utf-8',
      'json' => 'application/json',
      'wasm' => 'application/wasm',
      'svg' => 'image/svg+xml',
      'png' => 'image/png',
      'woff2' => 'font/woff2',
      'woff' => 'font/woff',
      _ => 'application/octet-stream',
    };
  }

  @visibleForTesting
  Future<void> close() => _server.close(force: true);
}
