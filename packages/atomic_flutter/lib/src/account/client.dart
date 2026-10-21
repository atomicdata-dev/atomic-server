import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:http/http.dart' as http;
import 'identity_handback.dart';

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

  /// The `session_token` cookie value when the session is a cookie one (an
  /// agent sign-in), for putting it in a web view; null for a bearer token.
  String? get sessionCookie => _cookie;

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

  /// The portal's drives live on its dashboard (`?drive=<id>` selects one).
  static const drivesPath = '/dashboard';

  /// The portal's Drives page. The portal has no chrome-less mode, so the app
  /// hides its nav bar itself. [portal] must be an HTTPS origin.
  static Uri portalDrivesUrl(Uri portal, {String? drive}) =>
      providerOrigin(portal.toString()).replace(
          path: drivesPath,
          queryParameters: drive == null ? null : {'drive': drive});

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

  /// Start a link. With [handback] the request carries a fresh in-memory
  /// X25519 public key (`app_key`), so the browser can seal the identity to
  /// this app (see [AtomicIdentityHandback]); [pollLink] then opens it.
  Future<AtomicDeviceLink> requestLink(String deviceName,
      {bool handback = false}) async {
    final key = handback ? await AtomicIdentityHandback.create() : null;
    final data = _object(
        await _request('POST', 'device-link', authenticated: false, body: {
      'device_name': deviceName,
      if (key != null) 'app_key': key.appKey,
    }));
    return AtomicDeviceLink.fromJson(data, origin, handback: key);
  }

  /// Where the web app lives for a portal: `app.` before the portal's host,
  /// as `https://app.atomic.place` belongs to `https://atomic.place`.
  static Uri appOrigin(Uri portal) {
    final host = portal.host;
    return portal.replace(
        host: host.startsWith('app.') ? host : 'app.$host',
        path: '',
        query: null,
        fragment: null);
  }

  AtomicRecoveredIdentity? _handedBack;

  /// The identity the browser sealed to this app, once, after [pollLink]
  /// reported approval; null when the portal approved without one (an older
  /// portal), in which case [recoverIdentity] is the way on.
  AtomicRecoveredIdentity? takeHandedBackIdentity() {
    final identity = _handedBack;
    _handedBack = null;
    return identity;
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
      final sealed = body['sealed_identity'];
      final key = request._handback;
      if (key != null && sealed is Map) {
        final opened = await key.openVerified(
            epk: sealed['epk'] as String,
            nonce: sealed['nonce'] as String,
            ciphertext: sealed['ciphertext'] as String);
        var address = '';
        try {
          final me = await account();
          address = '${me['address'] ?? me['email'] ?? ''}';
        } catch (_) {
          // Only a label; the identity is already verified.
        }
        _handedBack = AtomicRecoveredIdentity(
            subject: opened.subject,
            secret: opened.secret,
            address: address,
            drive: opened.drive);
      }
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
      throw const AtomicNoAssistedRecovery('This account has no backup yet.');
    }
    final data = _object(response);
    if (data['owner_email'] != me['email']) {
      throw StateError('Account backup belongs to another account');
    }
    if (data['format_version'] != 2 ||
        data['encryption_algorithm'] != 'AES-GCM') {
      throw const AtomicNoAssistedRecovery(
          'This account has an older backup the app cannot open.');
    }
    final wrappers = (data['wrappers'] as List?) ?? [];
    final wrapper = wrappers
        .whereType<Map<String, dynamic>>()
        .where((w) => w['wrapper_type'] == 'atomic-assisted')
        .firstOrNull;
    if (wrapper == null) {
      throw const AtomicNoAssistedRecovery();
    }
    final keyResponse =
        await _request('POST', 'recovery-secret/assisted-key', body: {
      'agent_subject': data['agent_subject'],
      'salt': wrapper['salt'],
    });
    if (keyResponse.statusCode == 403) {
      throw StateError('Sign in again in the browser to unlock this device');
    }
    // 410: the backup was made with a service key that has since been retired.
    if (keyResponse.statusCode == 410) {
      throw const AtomicNoAssistedRecovery(
          "This account's backup was made with a key that is no longer in use.");
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

  /// The account's AI credits, from the same `ai/status` the web Sync page
  /// reads. Null when the portal offers none (404/401) or AI is off for the
  /// account. Throws when the portal cannot be reached.
  Future<AtomicAiCredits?> aiCredits() async {
    final status = await aiStatus();
    if (status == null) return null;
    final credits = AtomicAiCredits.fromJson(status);
    return credits.enabled ? credits : null;
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
  }) =>
      completionText(chatCompletionChunks(messages, model: model));

  /// One streamed answer from the account's included AI, chunk by chunk: the
  /// decoded JSON of each `data:` line of the OpenAI-compatible
  /// `chat/completions` stream (`choices[0].delta` with `content` and
  /// `tool_calls`, `finish_reason`, `usage`). [messages] may carry tool calls
  /// and results, [tools] the functions the model may call (the portal
  /// passes them on; the caller runs them). Throws with the portal's own
  /// message when it refuses, and on an error chunk.
  Stream<Map<String, dynamic>> chatCompletionChunks(
    List<Map<String, dynamic>> messages, {
    required String model,
    List<Map<String, dynamic>>? tools,
  }) async* {
    if (!linked) throw StateError('Sign in first');
    final request =
        http.Request('POST', origin.replace(path: '/api/ai/chat/completions'))
          ..followRedirects = false
          ..headers['Content-Type'] = 'application/json'
          ..headers['Accept'] = 'text/event-stream'
          ..body = jsonEncode({
            'model': model,
            'messages': messages,
            'stream': true,
            if (tools != null && tools.isNotEmpty) ...{
              'tools': tools,
              'tool_choice': 'auto',
            },
          });
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
    yield* parseCompletionChunks(response.stream.transform(utf8.decoder));
  }

  /// The text deltas of a server-sent-events completion stream.
  static Stream<String> parseCompletionStream(Stream<String> chunks) =>
      completionText(parseCompletionChunks(chunks));

  /// The text deltas of decoded completion chunks.
  static Stream<String> completionText(
      Stream<Map<String, dynamic>> chunks) async* {
    await for (final json in chunks) {
      final choices = json['choices'];
      final delta = choices is List && choices.isNotEmpty
          ? (choices.first as Map)['delta']
          : null;
      final text = delta is Map ? delta['content'] : null;
      if (text is String && text.isNotEmpty) yield text;
    }
  }

  /// The decoded JSON chunks of a server-sent-events completion stream, up
  /// to `[DONE]`. Comments (`: OPENROUTER PROCESSING`) and lines that are not
  /// JSON are skipped; an error chunk throws.
  static Stream<Map<String, dynamic>> parseCompletionChunks(
      Stream<String> chunks) async* {
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
        Object? json;
        try {
          json = jsonDecode(data);
        } on FormatException {
          // A keep-alive comment or a partial line: nothing to show.
          continue;
        }
        if (json is! Map) continue;
        final error = json['error'];
        if (error != null) {
          throw StateError(error is Map
              ? '${error['message'] ?? 'Included AI failed'}'
              : '$error');
        }
        yield Map<String, dynamic>.from(json);
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

/// The account's identity can't be recovered by the app: there is no backup,
/// or it has no usable server-assisted wrapper, so only its recovery code or
/// passkey opens it, in the browser. Restoring there once adds the wrapper.
/// The app asks for the secret instead.
class AtomicNoAssistedRecovery implements Exception {
  final String reason;

  const AtomicNoAssistedRecovery(
      [this.reason =
          "This account's backup only opens with its recovery code or passkey."]);

  @override
  String toString() => '$reason Paste your Atomic secret, or restore once in '
      'the web app with your passkey or recovery code and try again.';
}

class AtomicDeviceLink {
  AtomicDeviceLink.fromJson(Map<String, dynamic> data, this.origin,
      {AtomicIdentityHandback? handback})
      : _handback = handback,
        _deviceCode = data['device_code'] as String,
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
  final AtomicIdentityHandback? _handback;

  /// Whether the browser is asked to hand the identity back.
  bool get wantsIdentity => _handback != null;
  Uri get approvalUrl =>
      origin.replace(path: '/link', queryParameters: {'code': userCode});

  /// The web app page that sends the identity to this app. [appOrigin] is
  /// [AtomicAccountClient.appOrigin] of the portal.
  Uri sendIdentityUrl(Uri appOrigin) => appOrigin
      .replace(path: '/app/send-identity', queryParameters: {'code': userCode});
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

/// The account's included-AI credits, as the portal's `ai/status` reports
/// them. Amounts are micros; one credit is 1000 micros.
class AtomicAiCredits {
  const AtomicAiCredits({
    required this.enabled,
    required this.allowanceMicros,
    required this.remainingMicros,
    this.purchasedMicros = 0,
    this.purchasesEnabled = false,
    this.resetsAt,
  });

  factory AtomicAiCredits.fromJson(Map<String, dynamic> json) {
    int n(String key) => (json[key] as num?)?.toInt() ?? 0;
    final resets = (json['resets_at'] as num?)?.toInt();
    return AtomicAiCredits(
      enabled: json['enabled'] == true,
      allowanceMicros: n('allowance_micros'),
      remainingMicros: n('remaining_micros'),
      purchasedMicros: n('purchased_remaining_micros'),
      purchasesEnabled: json['purchases_enabled'] == true,
      resetsAt: resets == null
          ? null
          : DateTime.fromMillisecondsSinceEpoch(resets * 1000, isUtc: true),
    );
  }

  final bool enabled;
  final int allowanceMicros;

  /// Monthly and purchased credits together.
  final int remainingMicros;
  final int purchasedMicros;
  final bool purchasesEnabled;
  final DateTime? resetsAt;

  /// Whole credits left, as the web app shows them.
  int get remaining => remainingMicros ~/ 1000;
  int get allowance => allowanceMicros ~/ 1000;
  int get purchased => purchasedMicros ~/ 1000;
}
