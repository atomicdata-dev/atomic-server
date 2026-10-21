import 'dart:convert';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

import 'atomic_auth.dart' show decodeAtomicBase64, encodeAtomicBase64;

/// A pasted secret that cannot be one, with a sentence that says what is
/// wrong and what to do.
class SecretFormatException implements Exception {
  const SecretFormatException(this.message);
  final String message;
  @override
  String toString() => message;
}

const _whereToFindIt = 'On a device or browser that is signed in, open '
    'Settings and copy your secret, then paste it here.';

/// Turns what was pasted into the secret it carries, or throws a
/// [SecretFormatException] that says in plain words what is wrong.
///
/// Accepts what people actually paste: surrounding spaces, newlines and tabs
/// (also inside a secret that a mail or notes app wrapped), quotes, a
/// `secret:` label, the URL-safe alphabet, missing `=` padding, the decoded
/// JSON itself, and a bare Ed25519 private key (the agent is derived from it).
/// The result is a standard secret: base64 of `{"privateKey", "subject", …}`.
String normalizeSecret(String raw) {
  var s = raw.trim();
  // Labels and wrappers copied along with the value.
  for (var i = 0; i < 3; i++) {
    final before = s;
    s = s
        .replaceFirst(
            RegExp(r'^(atomic\s+)?(agent\s+)?secret\s*(key)?\s*[:=]\s*',
                caseSensitive: false),
            '')
        .trim();
    if (s.length >= 2) {
      final quotes = {'"': '"', "'": "'", '`': '`', '“': '”', '‘': '’'};
      final close = quotes[s[0]];
      if (close != null && s.endsWith(close)) {
        s = s.substring(1, s.length - 1).trim();
      }
    }
    if (s == before) break;
  }
  if (s.isEmpty) throw const SecretFormatException('Paste your secret');

  // The decoded secret, pasted as JSON.
  if (s.startsWith('{')) {
    return _fromJson(s, pastedJson: true);
  }

  final lower = s.toLowerCase();
  if (lower.startsWith('did:ad:agent:') ||
      lower.startsWith('atomic:agent:') ||
      RegExp(r'^https?://\S+/agents/').hasMatch(s)) {
    throw const SecretFormatException(
        'That is your agent ID, which is public. Signing in needs your '
        'secret, the long private code. $_whereToFindIt');
  }
  if (lower.startsWith('http://') || lower.startsWith('https://')) {
    throw const SecretFormatException(
        'That is a link, not a secret. $_whereToFindIt');
  }
  if (lower.startsWith('did:') || lower.startsWith('atomic:')) {
    throw const SecretFormatException(
        'That is an ID of a drive or resource, not your secret. '
        '$_whereToFindIt');
  }

  // Whitespace and invisible characters a wrapped or copied line picks up.
  final compact = s.replaceAll(RegExp(r'[\s ​‌‍⁠﻿]'), '');
  final bad = RegExp(r'[^A-Za-z0-9+/\-_=]').firstMatch(compact);
  if (bad != null) {
    throw SecretFormatException(
        'That is not a secret: it contains "${bad.group(0)}", which a secret '
        'never has. $_whereToFindIt');
  }

  final List<int> bytes;
  try {
    bytes = decodeAtomicBase64(compact.replaceAll('=', ''));
  } catch (_) {
    throw const SecretFormatException(
        'That secret looks cut off: part of it is missing. Copy the whole '
        'secret again and paste it here.');
  }

  // A bare private key: 32 bytes.
  if (bytes.length == 32) {
    final key = ed.newKeyFromSeed(Uint8List.fromList(bytes));
    final public = encodeAtomicBase64(ed.public(key).bytes);
    return base64Encode(utf8.encode(jsonEncode({
      'privateKey': encodeAtomicBase64(bytes),
      'subject': 'atomic:agent:$public',
    })));
  }

  final String json;
  try {
    json = utf8.decode(bytes);
  } catch (_) {
    throw const SecretFormatException(
        'That is not a secret, or it was cut off when it was copied. Copy the '
        'whole secret again and paste it here.');
  }
  if (!json.trimLeft().startsWith('{')) {
    throw const SecretFormatException(
        'That is not a secret, or it was cut off when it was copied. Copy the '
        'whole secret again and paste it here.');
  }
  return _fromJson(json, pastedJson: false, original: compact);
}

String _fromJson(String json, {required bool pastedJson, String? original}) {
  Object? decoded;
  try {
    decoded = jsonDecode(json);
  } catch (_) {
    throw const SecretFormatException(
        'That secret looks cut off: part of it is missing. Copy the whole '
        'secret again and paste it here.');
  }
  if (decoded is! Map) {
    throw const SecretFormatException('That is not a secret. $_whereToFindIt');
  }
  final privateKey = decoded['privateKey'];
  final subject = decoded['subject'];
  if (privateKey is! String || privateKey.isEmpty) {
    throw const SecretFormatException(
        'That secret has no private key in it. $_whereToFindIt');
  }
  if (subject is! String || subject.isEmpty) {
    throw const SecretFormatException(
        'That secret does not say which agent it belongs to. $_whereToFindIt');
  }
  List<int> key;
  try {
    key = decodeAtomicBase64(privateKey.replaceAll('=', ''));
  } catch (_) {
    key = const [];
  }
  if (key.length != 32) {
    throw const SecretFormatException(
        'That secret is damaged: its private key is the wrong length. Copy '
        'the whole secret again and paste it here.');
  }
  // Unchanged when it came as a secret: the host reads either alphabet.
  if (!pastedJson && original != null) return original;
  return base64Encode(utf8.encode(jsonEncode(decoded)));
}
