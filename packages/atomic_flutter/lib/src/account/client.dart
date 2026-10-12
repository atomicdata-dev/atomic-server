import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:http/http.dart' as http;

/// Explicit, provider-neutral account linking. Constructing this client never
/// makes a network request. Credentials stay bound to one HTTPS origin.
class AtomicAccountClient {
  AtomicAccountClient(String provider, {http.Client? client})
      : origin = providerOrigin(provider),
        _http = client ?? http.Client();
  final Uri origin;
  final http.Client _http;
  String? _token;
  bool get linked => _token != null;

  static Uri providerOrigin(String input) {
    final uri = Uri.tryParse(input);
    if (uri == null ||
        uri.scheme != 'https' ||
        uri.host.isEmpty ||
        uri.userInfo.isNotEmpty ||
        uri.hasQuery ||
        uri.hasFragment ||
        (uri.path.isNotEmpty && uri.path != '/')) {
      throw ArgumentError('An account provider must be an HTTPS origin');
    }
    return uri.replace(path: '', query: null, fragment: null);
  }

  /// Only the host credential store should persist this value, never UI/logs.
  String exportSession() =>
      jsonEncode({'origin': origin.toString(), 'token': _token});
  void restoreSession(String saved) {
    final data = jsonDecode(saved) as Map<String, dynamic>;
    if (providerOrigin(data['origin'] as String) != origin ||
        data['token'] is! String ||
        (data['token'] as String).isEmpty) {
      throw StateError('This session belongs to another provider');
    }
    _token = data['token'] as String;
  }

  void forgetSession() => _token = null;
  void close() => _http.close();

  Future<http.Response> _request(String method, String path,
      {Map<String, dynamic>? body, bool authenticated = true}) async {
    if (authenticated && _token == null) throw StateError('Sign in first');
    final req = http.Request(method, origin.replace(path: '/api/$path'))
      ..followRedirects = false
      ..headers['Accept'] = 'application/json';
    if (authenticated) req.headers['Authorization'] = 'Bearer $_token';
    if (body != null) {
      req.headers['Content-Type'] = 'application/json';
      req.body = jsonEncode(body);
    }
    try {
      return await (() async =>
              http.Response.fromStream(await _http.send(req)))()
          .timeout(const Duration(seconds: 20));
    } catch (_) {
      // Network exceptions can contain the polling URL, including device_code.
      throw StateError('Could not reach the account provider');
    }
  }

  dynamic _decode(String body) {
    try {
      return jsonDecode(body);
    } catch (_) {
      throw const FormatException('Invalid account response');
    }
  }

  Map<String, dynamic> _object(http.Response response) {
    if (response.statusCode < 200 || response.statusCode >= 300) {
      if (response.statusCode == 401) {
        throw StateError('Sign in again to continue');
      }
      if (response.statusCode == 429) {
        throw StateError('Too many attempts. Try again shortly');
      }
      throw StateError('Account request failed (${response.statusCode})');
    }
    final value = _decode(response.body);
    if (value is! Map<String, dynamic>) {
      throw const FormatException('Invalid account response');
    }
    return value;
  }

  Future<AtomicDeviceLink> requestLink(String deviceName) async {
    final data = _object(await _request('POST', 'device-link',
        authenticated: false, body: {'device_name': deviceName}));
    return AtomicDeviceLink.fromJson(data, origin);
  }

  Future<AtomicLinkProgress> pollLink(AtomicDeviceLink request) async {
    if (request.origin != origin) {
      throw StateError('Link belongs to another provider');
    }
    if (DateTime.now().isAfter(request.expiresAt)) {
      return AtomicLinkProgress.expired;
    }
    final response = await _request(
        'GET', 'device-link/${Uri.encodeComponent(request._deviceCode)}',
        authenticated: false);
    if (response.statusCode == 404) return AtomicLinkProgress.expired;
    final body = _object(response);
    if (body['state'] == 'approved') {
      final token = body['token'];
      if (token is! String || token.isEmpty) {
        throw const FormatException('Missing account session');
      }
      _token = token;
      return AtomicLinkProgress.approved;
    }
    if (body['state'] != 'pending') {
      throw const FormatException('Invalid link state');
    }
    return AtomicLinkProgress.pending;
  }

  Future<Map<String, dynamic>> account() async =>
      _object(await _request('GET', 'me'));

  /// Recover the existing identity; never creates or replaces a user's backup.
  /// Passkey/code-only accounts must use their existing manual recovery path.
  Future<AtomicRecoveredIdentity> recoverIdentity() async {
    final me = await account();
    final response = await _request('GET', 'recovery-secret');
    if (response.statusCode == 404 || response.statusCode == 204) {
      throw StateError('Finish setting up your workspace in the browser first');
    }
    final data = _object(response);
    if (data['owner_email'] != me['email']) {
      throw StateError('Account backup belongs to another account');
    }
    if (data['format_version'] != 2 ||
        data['encryption_algorithm'] != 'AES-GCM') {
      throw StateError('This backup needs manual recovery in the browser');
    }
    final wrappers = (data['wrappers'] as List?) ?? [];
    final wrapper = wrappers
        .whereType<Map<String, dynamic>>()
        .where((w) => w['wrapper_type'] == 'atomic-assisted')
        .firstOrNull;
    if (wrapper == null) {
      throw StateError(
          'Use your recovery code or passkey in the browser, then import your Atomic secret');
    }
    final keyResponse =
        await _request('POST', 'recovery-secret/assisted-key', body: {
      'agent_subject': data['agent_subject'],
      'salt': wrapper['salt'],
    });
    if (keyResponse.statusCode == 403) {
      throw StateError('Sign in again in the browser to unlock this device');
    }
    final key = _object(keyResponse);
    final secret =
        await openAssistedEnvelope(data, wrapper, key['key'] as String);
    return AtomicRecoveredIdentity(
      subject: data['agent_subject'] as String,
      secret: secret,
      address: (me['address'] ?? me['email']) as String,
      drive: data['drive_subject'] as String?,
    );
  }

  Future<List<Map<String, dynamic>>> _list(String path, String key) async {
    final response = await _request('GET', path);
    if (response.statusCode != 200) {
      _object(response);
    }
    final data = _decode(response.body);
    final list = data is List
        ? data
        : data is Map
            ? data[key]
            : null;
    if (list is! List) throw const FormatException('Invalid account list');
    return list.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  Future<List<Map<String, dynamic>>> devices() => _list('devices', 'devices');
  Future<List<Map<String, dynamic>>> enrollments() =>
      _list('sync-enrollments', 'enrollments');

  /// Pure authenticated decryption, compatible with the browser's WebCrypto
  /// envelope-v2. AES-GCM stores the 16-byte tag after the ciphertext.
  static Future<String> openAssistedEnvelope(Map<String, dynamic> envelope,
      Map<String, dynamic> wrapper, String encodedKey) async {
    Future<List<int>> open(String cipher, String nonce, List<int> key) async {
      final bytes = base64Decode(cipher);
      final iv = base64Decode(nonce);
      if (bytes.length < 16 || iv.length != 12 || key.length != 32) {
        throw const FormatException('Invalid encrypted identity');
      }
      return AesGcm.with256bits().decrypt(
          SecretBox(bytes.sublist(0, bytes.length - 16),
              nonce: iv, mac: Mac(bytes.sublist(bytes.length - 16))),
          secretKey: SecretKey(key));
    }

    try {
      final dek = await open(wrapper['wrapped_dek'] as String,
          wrapper['wrap_nonce'] as String, base64Decode(encodedKey));
      return utf8.decode(await open(envelope['encrypted_secret'] as String,
          envelope['nonce'] as String, dek));
    } catch (_) {
      throw StateError('Your account could not unlock this backup');
    }
  }
}

enum AtomicLinkProgress { pending, approved, expired }

class AtomicDeviceLink {
  AtomicDeviceLink.fromJson(Map<String, dynamic> data, this.origin)
      : _deviceCode = data['device_code'] as String,
        userCode = data['user_code'] as String,
        interval = Duration(seconds: (data['interval'] as int).clamp(1, 3600)),
        expiresAt = DateTime.now().add(
            Duration(seconds: (data['expires_in'] as int).clamp(1, 3600))) {
    if (_deviceCode.isEmpty || userCode.isEmpty) {
      throw const FormatException('Invalid device link');
    }
  }
  final Uri origin;
  final String _deviceCode, userCode;
  final Duration interval;
  final DateTime expiresAt;
  Uri get approvalUrl =>
      origin.replace(path: '/link', queryParameters: {'code': userCode});
}

/// Carries a credential: deliberately has no Debug/toString serialization.
class AtomicRecoveredIdentity {
  AtomicRecoveredIdentity(
      {required this.subject,
      required this.secret,
      required this.address,
      this.drive});
  final String subject, secret, address;
  final String? drive;
}
