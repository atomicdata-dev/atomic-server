/// Request signing, for the endpoints that check who is asking.
///
/// Pure Dart on purpose: the same code signs on mobile and on web, and needs
/// nothing from the Rust bridge. The agent secret already lives in
/// [AtomicSession], so Dart can sign without asking Rust for the key.
///
/// The scheme is the one `atomic_lib`'s `get_authentication_headers` and
/// @tomic/lib's `signRequest` implement: sign `"<url> <timestamp>"` and send
/// the signature, public key, timestamp and agent alongside it. The server
/// rebuilds the message from the request it received — query string included —
/// so the URL signed must be the exact URL fetched.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

/// Base64 as Atomic writes it: URL-safe, unpadded — matching `encode_base64`
/// in `atomic_lib`. Keys and signatures travel in URLs and DIDs, so the
/// standard alphabet's `+/=` would need escaping.
String encodeAtomicBase64(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

/// Base64 as Atomic reads it: either alphabet, padded or not.
///
/// Deliberately more tolerant than [encodeAtomicBase64] writes, mirroring
/// `decode_base64` — secrets and keys minted by older clients (or pasted by
/// hand) come in both alphabets, and a decoder is the wrong place to be strict.
Uint8List decodeAtomicBase64(String input) {
  final standard = input.replaceAll('-', '+').replaceAll('_', '/');
  final remainder = standard.length % 4;
  final padded = remainder == 0 ? standard : standard + '=' * (4 - remainder);

  return base64Decode(padded);
}

/// An agent's keys, as carried in the one-string secret.
class AtomicAgent {
  const AtomicAgent({
    required this.subject,
    required this.privateKeyB64,
    required this.publicKeyB64,
  });

  final String subject;
  final String privateKeyB64;
  final String publicKeyB64;

  /// Reads the base64-encoded JSON secret that `setup()` hands out.
  factory AtomicAgent.fromSecret(String secret) {
    final decoded = jsonDecode(utf8.decode(decodeAtomicBase64(secret)))
        as Map<String, dynamic>;
    final privateKeyB64 = decoded['privateKey'] as String;
    final privateKey = ed.newKeyFromSeed(decodeAtomicBase64(privateKeyB64));

    return AtomicAgent(
      subject: decoded['subject'] as String,
      privateKeyB64: privateKeyB64,
      publicKeyB64: encodeAtomicBase64(ed.public(privateKey).bytes),
    );
  }
}

/// Signs `message` with the agent's private key.
String signMessage(String message, String privateKeyB64) =>
    signBytes(Uint8List.fromList(utf8.encode(message)), privateKeyB64);

/// Signs raw bytes with the agent's private key.
String signBytes(Uint8List message, String privateKeyB64) {
  final privateKey = ed.newKeyFromSeed(decodeAtomicBase64(privateKeyB64));
  final signature = ed.sign(privateKey, message);

  // ed.sign returns the 64-byte signature followed by the message itself.
  return encodeAtomicBase64(signature.sublist(0, 64));
}

/// Headers proving to `url`'s server that this agent is asking.
///
/// `url` must be the whole URL being fetched, query string and all.
Map<String, String> signedHeaders(String url, AtomicAgent agent) {
  final timestamp = DateTime.now().millisecondsSinceEpoch;

  return {
    'x-atomic-public-key': agent.publicKeyB64,
    'x-atomic-signature': signMessage('$url $timestamp', agent.privateKeyB64),
    'x-atomic-timestamp': '$timestamp',
    'x-atomic-agent': agent.subject,
  };
}
