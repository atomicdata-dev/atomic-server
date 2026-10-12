// Command-line proxy; stdout is its user interface.
// ignore_for_file: avoid_print
// Reverse proxy that adds COOP/COEP headers for SharedArrayBuffer support.
// Usage: dart run web_proxy.dart <flutter_port> [proxy_port]

import 'dart:io';
import 'dart:async';

void main(List<String> args) async {
  if (args.isEmpty) {
    print('Usage: dart run web_proxy.dart <flutter_port> [proxy_port]');
    exit(1);
  }
  final targetPort = int.parse(args[0]);
  final proxyPort = args.length > 1 ? int.parse(args[1]) : 8080;

  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, proxyPort);
  print('COOP/COEP proxy: http://localhost:$proxyPort -> http://localhost:$targetPort');

  final client = HttpClient();

  await for (final request in server) {
    _handleRequest(request, client, targetPort);
  }
}

Future<void> _handleRequest(
    HttpRequest request, HttpClient client, int targetPort) async {
  try {
    final url = Uri.parse('http://localhost:$targetPort${request.uri}');
    final proxyReq = await client.openUrl(request.method, url);

    // Forward request headers
    request.headers.forEach((name, values) {
      if (name.toLowerCase() == 'host') return;
      for (final v in values) {
        proxyReq.headers.add(name, v);
      }
    });
    proxyReq.headers.set('host', 'localhost:$targetPort');

    // Forward request body
    await for (final chunk in request) {
      proxyReq.add(chunk);
    }
    final proxyResp = await proxyReq.close();

    // Forward response status and headers
    request.response.statusCode = proxyResp.statusCode;
    proxyResp.headers.forEach((name, values) {
      for (final v in values) {
        request.response.headers.add(name, v);
      }
    });

    // Inject cross-origin isolation headers
    request.response.headers.set('Cross-Origin-Opener-Policy', 'same-origin');
    request.response.headers.set('Cross-Origin-Embedder-Policy', 'credentialless');

    // Stream response body
    await proxyResp.pipe(request.response);
  } catch (e) {
    try {
      request.response.statusCode = 502;
      request.response.write('Proxy error: $e');
      await request.response.close();
    } catch (_) {}
  }
}
