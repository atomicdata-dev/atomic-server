import 'dart:convert';

import 'package:atomic_app/atomic/atomic_auth.dart';
import 'package:atomic_app/atomic/secret_input.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:flutter_test/flutter_test.dart';

/// A fresh test identity: never a real one.
({String secret, String privateKey, String publicKey}) _testSecret() {
  final pair = ed.generateKey();
  final seed = ed.seed(pair.privateKey);
  final privateKey = base64Encode(seed);
  final publicKey = encodeAtomicBase64(pair.publicKey.bytes);
  final json = jsonEncode({
    'privateKey': privateKey,
    'subject': 'did:ad:agent:$publicKey',
  });
  return (
    secret: base64Encode(utf8.encode(json)),
    privateKey: privateKey,
    publicKey: publicKey,
  );
}

String _message(String input) {
  try {
    normalizeSecret(input);
  } on SecretFormatException catch (e) {
    return e.message;
  }
  fail('expected $input to be refused');
}

void main() {
  final t = _testSecret();

  group('accepted as pasted', () {
    test('as it is', () => expect(normalizeSecret(t.secret), t.secret));

    final variants = {
      'trailing spaces (the web settings copy)': '${t.secret}   ',
      'newlines around it': '\n${t.secret}\n',
      'CRLF and tabs': '\t${t.secret}\r\n',
      'wrapped over lines by a mail app':
          '${t.secret.substring(0, 30)}\n${t.secret.substring(30, 70)}\n${t.secret.substring(70)}',
      'double quotes': '"${t.secret}"',
      'single quotes': "'${t.secret}'",
      'smart quotes': '“${t.secret}”',
      'backticks': '`${t.secret}`',
      'a secret: label': 'secret: ${t.secret}',
      'an Agent secret = label': 'Agent secret = ${t.secret}',
      'a label and quotes': 'Secret: "${t.secret}"',
      'non-breaking and zero-width spaces':
          ' ${t.secret.substring(0, 10)}​${t.secret.substring(10)}﻿',
      'without = padding': t.secret.replaceAll('=', ''),
    };
    variants.forEach((name, input) {
      test(name, () {
        final out = normalizeSecret(input);
        final agent = AtomicAgent.fromSecret(out);
        expect(agent.subject, 'did:ad:agent:${t.publicKey}');
        expect(agent.publicKeyB64, t.publicKey);
      });
    });

    test('the URL-safe alphabet', () {
      final urlSafe = t.secret
          .replaceAll('+', '-')
          .replaceAll('/', '_')
          .replaceAll('=', '');
      expect(AtomicAgent.fromSecret(normalizeSecret(urlSafe)).publicKeyB64,
          t.publicKey);
    });

    test('the decoded JSON itself', () {
      final json = utf8.decode(base64Decode(t.secret));
      final out = normalizeSecret('  $json\n');
      expect(AtomicAgent.fromSecret(out).publicKeyB64, t.publicKey);
    });

    test('a bare private key: the agent follows from it', () {
      final out = normalizeSecret(t.privateKey);
      final agent = AtomicAgent.fromSecret(out);
      expect(agent.publicKeyB64, t.publicKey);
      expect(agent.subject, 'atomic:agent:${t.publicKey}');
    });
  });

  group('refused in plain words', () {
    test('nothing', () => expect(_message('  \n '), 'Paste your secret'));

    test('the public agent ID', () {
      expect(_message('did:ad:agent:${t.publicKey}'),
          startsWith('That is your agent ID, which is public.'));
      expect(_message('atomic:agent:${t.publicKey}'),
          startsWith('That is your agent ID'));
      expect(_message('https://atomicdata.dev/agents/${t.publicKey}'),
          startsWith('That is your agent ID'));
    });

    test('a drive ID', () {
      expect(
          _message('did:ad:somedrive'), startsWith('That is an ID of a drive'));
    });

    test('a link', () {
      expect(_message('https://atomic.place/app/settings'),
          startsWith('That is a link, not a secret.'));
    });

    test('a word or sentence', () {
      expect(_message('my password!'), contains('which a secret never has'));
    });

    test('cut off when copied', () {
      expect(_message(t.secret.substring(0, t.secret.length - 9)),
          anyOf(contains('cut off'), contains('wrong length')));
      expect(_message(t.secret.substring(0, 41)), contains('cut off'));
    });

    test('base64 that is not a secret', () {
      expect(_message(base64Encode(utf8.encode('hello there, friend'))),
          contains('not a secret'));
    });

    test('JSON without a key', () {
      expect(
          _message(base64Encode(utf8.encode('{"subject":"did:ad:agent:x"}'))),
          contains('no private key'));
    });

    test('a damaged key', () {
      final json = jsonEncode({
        'privateKey': t.privateKey.substring(0, 20),
        'subject': 'did:ad:agent:${t.publicKey}',
      });
      expect(
          _message(base64Encode(utf8.encode(json))), contains('wrong length'));
    });

    test('no message names a decoder', () {
      for (final input in ['x', 'abc!', t.secret.substring(0, 13), '{nope']) {
        final m = _message(input);
        expect(m, isNot(contains('Base64')));
        expect(m, isNot(contains('FormatException')));
      }
    });
  });
}
