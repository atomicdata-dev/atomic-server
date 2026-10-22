import 'dart:convert';
import 'dart:typed_data';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:http/http.dart' as http;
import 'atomic_client.dart';

String? _serverUrl;
String? _privateKeyB64;
String? _publicKeyB64;
String? _agentSubject;
String? _driveSubject;

const _isA = 'https://atomicdata.dev/properties/isA';
const _name = 'https://atomicdata.dev/properties/name';
const _subject = 'https://atomicdata.dev/properties/subject';
const _createdAt = 'https://atomicdata.dev/properties/createdAt';
const _signer = 'https://atomicdata.dev/properties/signer';
const _signature = 'https://atomicdata.dev/properties/signature';
const _isGenesis = 'https://atomicdata.dev/properties/isGenesis';
const _read = 'https://atomicdata.dev/properties/read';
const _write = 'https://atomicdata.dev/properties/write';
const _publicAgent = 'https://atomicdata.dev/agents/publicAgent';
const _driveClass = 'https://atomicdata.dev/classes/Drive';

// ── Agent ──────────────────────────────────────────────────────────────────

AgentInfo createAgent(String name) {
  final keyPair = ed.generateKey();
  final privateKeyB64 = base64Encode(ed.seed(keyPair.privateKey));
  final publicKeyB64 = base64Encode(keyPair.publicKey.bytes);
  final subject = 'atomic:agent:$publicKeyB64';
  final secret = base64Encode(utf8.encode(jsonEncode({
    'privateKey': privateKeyB64,
    'subject': subject,
  })));
  return AgentInfo(
      secret: secret, subject: subject, publicKey: publicKeyB64, name: name);
}

AgentInfo agentFromSecret(String secret) {
  final decoded =
      jsonDecode(utf8.decode(base64Decode(secret))) as Map<String, dynamic>;
  final privKey = decoded['privateKey'] as String;
  final subject = decoded['subject'] as String;
  final seedBytes = Uint8List.fromList(base64Decode(privKey));
  final privateKey = ed.newKeyFromSeed(seedBytes);
  final publicKeyB64 = base64Encode(ed.public(privateKey).bytes);
  return AgentInfo(
      secret: secret, subject: subject, publicKey: publicKeyB64, name: null);
}

// ── Signing ────────────────────────────────────────────────────────────────

String _signMessage(String message, String privateKeyB64, String publicKeyB64) {
  final seedBytes = Uint8List.fromList(base64Decode(privateKeyB64));
  final privateKey = ed.newKeyFromSeed(seedBytes);
  final msgBytes = Uint8List.fromList(utf8.encode(message));
  final sig = ed.sign(privateKey, msgBytes);
  // ed.sign returns signature (64 bytes) + message. Take first 64 bytes.
  return base64Encode(sig.sublist(0, 64));
}

/// Serialize a map with sorted keys (JCS-like).
String _jcs(Map<String, dynamic> map) {
  final sorted = Map.fromEntries(
      map.entries.toList()..sort((a, b) => a.key.compareTo(b.key)));
  return jsonEncode(sorted);
}

int _now() => DateTime.now().millisecondsSinceEpoch;

/// Post a genesis commit (creates a new DID resource). Returns the subject.
Future<String> _postGenesisCommit(Map<String, dynamic> properties) async {
  final commitMap = <String, dynamic>{
    _signer: _agentSubject,
    _createdAt: _now(),
    _isGenesis: true,
  };

  // Add all properties
  for (final e in properties.entries) {
    commitMap[e.key] = e.value;
  }

  // Serialize without @id and signature for signing
  final toSign = _jcs(commitMap);
  final sig = _signMessage(toSign, _privateKeyB64!, _publicKeyB64!);
  final did = 'atomic:$sig';

  commitMap[_subject] = did;
  commitMap[_signature] = sig;
  commitMap['@id'] = did;

  // Post without @id (server derives it)
  final body = Map<String, dynamic>.from(commitMap)..remove('@id');

  final resp = await http.post(
    Uri.parse('$_serverUrl/commit'),
    headers: {'Content-Type': 'application/json'},
    body: _jcs(body),
  );
  if (resp.statusCode != 200) {
    throw Exception('Commit failed (${resp.statusCode}): ${resp.body}');
  }
  return did;
}

// ── Connection ─────────────────────────────────────────────────────────────

Future<String> connect(String serverUrl, String agentSecret) async {
  final info = agentFromSecret(agentSecret);
  _serverUrl = serverUrl;
  _privateKeyB64 = (jsonDecode(utf8.decode(base64Decode(agentSecret)))
      as Map<String, dynamic>)['privateKey'] as String;
  _publicKeyB64 = info.publicKey;
  _agentSubject = info.subject;
  return info.subject;
}

Future<String> createDrive(String name) async {
  final did = await _postGenesisCommit({
    _isA: [_driveClass],
    _name: name,
    _write: [_agentSubject],
    _read: [_publicAgent],
  });
  _driveSubject = did;
  return did;
}

void setDrive(String subject) => _driveSubject = subject;
String? getDrive() => _driveSubject;
