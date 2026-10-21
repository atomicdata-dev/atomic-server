import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

/// The app's half of the identity hand-back (planning/flutter-secret-handback.md):
/// the browser unlocks the account's backup and seals the secret to a key that
/// exists only in this app's memory, so the provider relays ciphertext.
///
/// Scheme: ephemeral sender X25519, ECDH with the app key, HKDF-SHA256 (empty
/// salt, info = label || app_key || epk), AES-256-GCM, 12-byte nonce. The
/// browser twin is `identityHandback.ts` in the data-browser; both are tested
/// against `test/fixtures/identity_handback_vector.json`.
class AtomicIdentityHandback {
  AtomicIdentityHandback._(this._pair, this.publicKey);

  final SimpleKeyPair _pair;

  /// The raw 32-byte X25519 public key to send as `app_key`.
  final Uint8List publicKey;

  static const _label = 'atomic-identity-handback-v1';

  /// A fresh key pair, one per attempt. Keep it in memory only.
  static Future<AtomicIdentityHandback> create({List<int>? seed}) async {
    final pair = await (seed == null
        ? X25519().newKeyPair()
        : X25519().newKeyPairFromSeed(seed));
    final pub = await pair.extractPublicKey();
    return AtomicIdentityHandback._(pair, Uint8List.fromList(pub.bytes));
  }

  /// `app_key` as the provider wants it: unpadded base64url.
  String get appKey => base64UrlNoPad(publicKey);

  /// Decrypt a sealed identity from the browser. Throws [StateError] for
  /// anything that does not authenticate; checks nothing about the contents,
  /// see [openVerified] for that.
  Future<Map<String, dynamic>> open(
      {required String epk,
      required String nonce,
      required String ciphertext}) async {
    try {
      final senderPublic = decodeBase64Url(epk);
      final iv = decodeBase64Url(nonce);
      final bytes = decodeBase64Url(ciphertext);
      if (senderPublic.length != 32 || iv.length != 12 || bytes.length < 16) {
        throw const FormatException('bad sizes');
      }
      final key = await _derive(_pair, senderPublic, publicKey, senderPublic);
      final clear = await AesGcm.with256bits().decrypt(
          SecretBox(bytes.sublist(0, bytes.length - 16),
              nonce: iv, mac: Mac(bytes.sublist(bytes.length - 16))),
          secretKey: key);
      final payload = jsonDecode(utf8.decode(clear));
      if (payload is! Map<String, dynamic>) {
        throw const FormatException('shape');
      }
      return payload;
    } catch (_) {
      throw StateError('The identity from the browser could not be opened');
    }
  }

  /// [open], then check that the secret really is the agent named by
  /// `subject`: its private key must derive that public key. A browser (or
  /// anything on the way) that sent another identity is refused.
  Future<AtomicHandedBackSecret> openVerified(
      {required String epk,
      required String nonce,
      required String ciphertext}) async {
    final payload = await open(epk: epk, nonce: nonce, ciphertext: ciphertext);
    final secret = payload['secret'];
    final subject = payload['subject'];
    final drive = payload['drive'];
    if (secret is! String ||
        subject is! String ||
        (drive != null && drive is! String)) {
      throw StateError('The identity from the browser is incomplete');
    }
    if (!await secretMatchesSubject(secret, subject)) {
      throw StateError('The identity from the browser does not match');
    }
    return AtomicHandedBackSecret(
        secret: secret, subject: subject, drive: drive as String?);
  }

  /// For tests and the browser twin: encrypt as the sender would.
  static Future<Map<String, String>> seal(
    String appKey,
    Map<String, dynamic> payload, {
    List<int>? senderSeed,
    List<int>? nonce,
  }) async {
    final sender = await (senderSeed == null
        ? X25519().newKeyPair()
        : X25519().newKeyPairFromSeed(senderSeed));
    final epk = Uint8List.fromList((await sender.extractPublicKey()).bytes);
    final app = decodeBase64Url(appKey);
    final key = await _derive(sender, app, app, epk);
    final iv = nonce ?? AesGcm.with256bits().newNonce();
    final box = await AesGcm.with256bits()
        .encrypt(utf8.encode(jsonEncode(payload)), secretKey: key, nonce: iv);
    return {
      'epk': base64UrlNoPad(epk),
      'nonce': base64UrlNoPad(iv),
      'ciphertext': base64UrlNoPad([...box.cipherText, ...box.mac.bytes]),
    };
  }

  /// ECDH with [remote], then HKDF. Both sides bind the same `app_key` and
  /// `epk` into the key, whichever of them they are.
  static Future<SecretKey> _derive(SimpleKeyPair mine, List<int> remote,
      List<int> appKey, List<int> epk) async {
    final shared = await X25519().sharedSecretKey(
        keyPair: mine,
        remotePublicKey: SimplePublicKey(remote, type: KeyPairType.x25519));
    return Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
        secretKey: shared,
        nonce: const <int>[],
        info: [...utf8.encode(_label), ...appKey, ...epk]);
  }

  /// Does [secret] (base64 JSON with a `privateKey` seed) derive the public
  /// key that [subject] (`did:ad:agent:<key>` or a legacy URL) names?
  static Future<bool> secretMatchesSubject(
      String secret, String subject) async {
    try {
      final decoded = jsonDecode(utf8.decode(decodeBase64Url(secret)));
      final seed = decodeBase64Url((decoded as Map)['privateKey'] as String);
      final pair = await Ed25519().newKeyPairFromSeed(seed);
      final pub = (await pair.extractPublicKey()).bytes;
      final named = decodeBase64Url(subject.split(RegExp(r'[:/]')).last);
      return _same(pub, named);
    } catch (_) {
      return false;
    }
  }

  static bool _same(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  static String base64UrlNoPad(List<int> bytes) =>
      base64Url.encode(bytes).replaceAll('=', '');

  /// Either alphabet, padded or not.
  static Uint8List decodeBase64Url(String input) {
    final standard = input.replaceAll('-', '+').replaceAll('_', '/');
    final r = standard.length % 4;
    return base64Decode(r == 0 ? standard : standard + '=' * (4 - r));
  }
}

/// A secret the browser handed back, already checked against its subject.
/// Carries a credential: deliberately has no toString.
class AtomicHandedBackSecret {
  const AtomicHandedBackSecret(
      {required this.secret, required this.subject, this.drive});
  final String secret, subject;
  final String? drive;
}
