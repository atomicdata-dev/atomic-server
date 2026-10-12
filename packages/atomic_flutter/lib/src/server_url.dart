/// Server URL handling, shared by every screen that takes one from a user.
///
/// Kept in step with `normalizeServerUrl` / `sameOrigin` in the data-browser's
/// SyncRoute: the same URL typed into either client should mean the same thing.
library;

/// A server URL as typed by a person, made into one that can be fetched.
///
/// Requiring a scheme is a papercut — people type `localhost:9883`. Local
/// addresses get `http` (there is no certificate on a dev box), everything
/// else `https`. An explicit scheme is always kept.
String normalizeServerUrl(String input) {
  final trimmed = input.trim().replaceAll(RegExp(r'/+$'), '');

  if (RegExp(r'^https?://', caseSensitive: false).hasMatch(trimmed)) {
    return trimmed;
  }

  if (trimmed.isEmpty) {
    return '';
  }

  return '${isLocalAddress(trimmed) ? 'http' : 'https'}://$trimmed';
}

/// Whether `authority` (`host` or `host:port`) names a machine on this network
/// rather than the internet.
///
/// A phone cannot reach `localhost` — the dev server it wants is at the LAN
/// address of the machine running it, so treating only `localhost` as local
/// would default the one address a phone actually needs to `https`, which no
/// dev server speaks. Private ranges can't hold public certificates anyway.
bool isLocalAddress(String authority) {
  final host = authority.split(':').first.toLowerCase();

  if (host == 'localhost' || host == '::1' || host.endsWith('.local')) {
    return true;
  }

  final octets = host.split('.');

  if (octets.length != 4 || octets.any((o) => int.tryParse(o) == null)) {
    return false;
  }

  final [a, b, _, _] = octets.map(int.parse).toList();

  // The private ranges (RFC 1918) plus loopback.
  return a == 127 ||
      a == 10 ||
      (a == 192 && b == 168) ||
      (a == 172 && b >= 16 && b <= 31);
}

/// Whether two server URLs point at the same server — how "is this the one in
/// use?" is decided, tolerant of trailing slashes and paths.
bool sameOrigin(String a, String? b) {
  if (b == null || b.isEmpty) {
    return false;
  }

  try {
    final ua = Uri.parse(a);
    final ub = Uri.parse(b);

    return ua.scheme == ub.scheme && ua.host == ub.host && ua.port == ub.port;
  } catch (_) {
    return false;
  }
}

/// A server URL as shown to a person: the bare authority, keeping the port
/// (which distinguishes two dev servers) and dropping only the scheme.
String serverLabel(String url) {
  try {
    final parsed = Uri.parse(url);

    if (parsed.host.isEmpty) {
      return url;
    }

    return parsed.hasPort ? '${parsed.host}:${parsed.port}' : parsed.host;
  } catch (_) {
    return url;
  }
}
