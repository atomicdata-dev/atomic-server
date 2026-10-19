import 'dart:convert';
import 'dart:typed_data';
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

  /// The `session_token` cookie value of an agent sign-in, the alternative to
  /// a linked device's bearer token.
  String? _cookie;
  bool get linked => _token != null || _cookie != null;

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

  /// The portal a saved session belongs to.
  static Uri sessionOrigin(String saved) => providerOrigin(
      (jsonDecode(saved) as Map<String, dynamic>)['origin'] as String);

  /// Only the host credential store should persist this value, never UI/logs.
  String exportSession() => jsonEncode({
        'origin': origin.toString(),
        if (_token != null) 'token': _token else 'cookie': _cookie,
      });
  void restoreSession(String saved) {
    final data = jsonDecode(saved) as Map<String, dynamic>;
    final key = data['token'] is String ? 'token' : 'cookie';
    if (providerOrigin(data['origin'] as String) != origin ||
        data[key] is! String ||
        (data[key] as String).isEmpty) {
      throw StateError('This session belongs to another provider');
    }
    _token = key == 'token' ? data[key] as String : null;
    _cookie = key == 'cookie' ? data[key] as String : null;
  }

  void forgetSession() {
    _token = null;
    _cookie = null;
  }

  /// Sign in with the Atomic agent, as the web app does: the portal issues a
  /// challenge, [sign] signs `"<challenge> <timestamp>"` with the agent key,
  /// and the portal answers 204 with a session cookie. Returns false when the
  /// agent is not an account's identity (no session is created); throws when
  /// the portal cannot be reached.
  Future<bool> signInWithAgent(
      String agentSubject, Future<String> Function(String message) sign) async {
    final issued = await _request('POST', 'auth/agent/challenge',
        authenticated: false, body: {'agent_subject': agentSubject});
    if (issued.statusCode != 200) return false;
    final challenge = _decode(issued.body);
    if (challenge is! Map ||
        challenge['nonce'] is! String ||
        challenge['challenge'] is! String) {
      return false;
    }
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    final signature = await sign('${challenge['challenge']} $timestamp');
    final response = await _request('POST', 'auth/agent',
        query: {'if_linked': 'true'},
        authenticated: false,
        body: {
          'nonce': challenge['nonce'],
          'timestamp': timestamp,
          'signature': signature,
        });
    // Only 204 makes a session; 200 with signed_in:false means no account.
    if (response.statusCode != 204) return false;
    final cookie = RegExp(r'(?:^|[\s,])session_token=([^;,\s]+)')
        .firstMatch(response.headers['set-cookie'] ?? '')
        ?.group(1);
    if (cookie == null || cookie.isEmpty) return false;
    _token = null;
    _cookie = cookie;
    return true;
  }

  void close() => _http.close();

  Future<http.Response> _request(String method, String path,
      {Map<String, dynamic>? body,
      Map<String, String>? query,
      Duration timeout = const Duration(seconds: 20),
      bool authenticated = true}) async {
    if (authenticated && !linked) throw StateError('Sign in first');
    final req = http.Request(
        method, origin.replace(path: '/api/$path', queryParameters: query))
      ..followRedirects = false
      ..headers['Accept'] = 'application/json';
    if (authenticated) _authorize(req);
    if (body != null) {
      req.headers['Content-Type'] = 'application/json';
      req.body = jsonEncode(body);
    }
    try {
      return await (() async =>
              http.Response.fromStream(await _http.send(req)))()
          .timeout(timeout);
    } catch (_) {
      // Network exceptions can contain the polling URL, including device_code.
      throw StateError('Could not reach the account provider');
    }
  }

  /// A bearer token needs nothing more. A cookie session also names the portal
  /// as `Origin`, which the portal requires of cookie-authenticated writes.
  void _authorize(http.BaseRequest req) {
    if (_token != null) {
      req.headers['Authorization'] = 'Bearer $_token';
    } else {
      req.headers['Cookie'] = 'session_token=$_cookie';
      req.headers['Origin'] = origin.toString().replaceAll(RegExp(r'/$'), '');
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

  /// The account's included AI: whether it is on, consent, the model and the
  /// credits left. Null when the portal offers none (404) or the session is not
  /// valid (401).
  Future<Map<String, dynamic>?> aiStatus() async {
    final response = await _request('GET', 'ai/status');
    if (response.statusCode == 404 || response.statusCode == 401) return null;
    return _object(response);
  }

  /// Accept the included-AI terms for this account.
  Future<Map<String, dynamic>> aiConsent() async =>
      _object(await _request('POST', 'ai/consent', body: {'accepted': true}));

  /// Whether the account may transcribe speech (`enabled`) and the credits
  /// left (`remaining_micros`). Null when the portal offers none (404) or the
  /// session is not valid (401).
  Future<Map<String, dynamic>?> voiceStatus() async {
    final response = await _request('GET', 'ai/voice/status');
    if (response.statusCode == 404 || response.statusCode == 401) return null;
    return _object(response);
  }

  /// Transcribes [wav] (16-bit mono PCM WAV, as the data-browser sends it)
  /// with the account's Whisper, paid from its credits. [language] is an
  /// ISO-639-1 hint; null lets Whisper detect it. Returns the text, empty when
  /// nothing was heard. Throws [AtomicVoiceError].
  Future<String> transcribe(Uint8List wav, {String? language}) async {
    if (!linked) throw const AtomicVoiceError(AtomicVoiceFailure.notLinked);
    final http.Response response;
    try {
      response = await _request('POST', 'ai/voice',
          timeout: const Duration(seconds: 60),
          body: {
            'kind': 'transcribe',
            'data': base64Encode(wav),
            'accepted': true,
            if (language != null && language.isNotEmpty) 'language': language,
          });
    } catch (_) {
      throw const AtomicVoiceError(AtomicVoiceFailure.offline);
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      var message = '';
      try {
        final json = jsonDecode(response.body);
        if (json is Map && json['error'] is String) {
          message = json['error'] as String;
        }
      } catch (_) {}
      final failure = switch (response.statusCode) {
        401 => AtomicVoiceFailure.notLinked,
        402 => AtomicVoiceFailure.noCredits,
        _ when message.toLowerCase().contains('credit') =>
          AtomicVoiceFailure.noCredits,
        _ => AtomicVoiceFailure.server,
      };
      throw AtomicVoiceError(failure, message: message);
    }
    final json = _decode(response.body);
    final text = json is Map ? json['text'] : null;
    return text is String ? text.trim() : '';
  }

  /// One streamed answer from the account's included AI: the text deltas of an
  /// OpenAI-compatible `chat/completions` stream. Throws with the portal's own
  /// message when it refuses (no credits, no consent).
  Stream<String> chatCompletion(
    List<Map<String, String>> messages, {
    required String model,
  }) async* {
    if (!linked) throw StateError('Sign in first');
    final request = http.Request(
        'POST', origin.replace(path: '/api/ai/chat/completions'))
      ..followRedirects = false
      ..headers['Content-Type'] = 'application/json'
      ..headers['Accept'] = 'text/event-stream'
      ..body =
          jsonEncode({'model': model, 'messages': messages, 'stream': true});
    _authorize(request);
    final http.StreamedResponse response;
    try {
      response = await _http.send(request).timeout(const Duration(seconds: 30));
    } catch (_) {
      throw StateError('Could not reach the account provider');
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      final body = await response.stream.bytesToString();
      var message = 'Included AI is unavailable (${response.statusCode})';
      try {
        final json = jsonDecode(body);
        if (json is Map && json['error'] is String) {
          message = json['error'] as String;
        }
      } catch (_) {}
      if (response.statusCode == 401) message = 'Sign in again to continue';
      throw StateError(message);
    }
    yield* parseCompletionStream(response.stream.transform(utf8.decoder));
  }

  /// The text deltas of a server-sent-events completion stream.
  static Stream<String> parseCompletionStream(Stream<String> chunks) async* {
    var buffer = '';
    await for (final chunk in chunks) {
      buffer += chunk;
      while (true) {
        final newline = buffer.indexOf('\n');
        if (newline < 0) break;
        final line = buffer.substring(0, newline).trim();
        buffer = buffer.substring(newline + 1);
        if (!line.startsWith('data:')) continue;
        final data = line.substring(5).trim();
        if (data == '[DONE]') return;
        try {
          final json = jsonDecode(data);
          final choices = json is Map ? json['choices'] : null;
          final delta = choices is List && choices.isNotEmpty
              ? (choices.first as Map)['delta']
              : null;
          final text = delta is Map ? delta['content'] : null;
          if (text is String && text.isNotEmpty) yield text;
          final error = json is Map ? json['error'] : null;
          if (error != null) {
            throw StateError(error is Map
                ? '${error['message'] ?? 'Included AI failed'}'
                : '$error');
          }
        } on FormatException {
          // A keep-alive comment or a partial line: nothing to show.
        }
      }
    }
  }

  /// Cloud Vault enrollments: one blind, encrypted backup per drive.
  Future<List<Map<String, dynamic>>> vaultDrives() =>
      _list('cloud-vault/drives', 'drives');
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

/// Why a transcription did not happen.
enum AtomicVoiceFailure { notLinked, noCredits, offline, server }

class AtomicVoiceError implements Exception {
  const AtomicVoiceError(this.failure, {this.message = ''});
  final AtomicVoiceFailure failure;

  /// The portal's own words, when it gave any.
  final String message;

  @override
  String toString() => 'AtomicVoiceError($failure)';
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
