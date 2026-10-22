import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';

import 'package:atomic_app/atomic/own_profile.dart';

String _json(Map<String, Object?> m) => jsonEncode(m);

void main() {
  setUp(OwnProfile.forgetFetched);

  test('a url picture', () async {
    final p = await OwnProfile.load(
        readProfile: () async =>
            _json({'name': 'Joep', 'imageUrl': 'https://a.test/me.png'}),
        readBytes: (_) async => fail('no file'));
    expect(p.imageUrl, 'https://a.test/me.png');
    expect(p.imageBytes, isNull);
    expect(p.pendingImage, isFalse);
  });

  test('a File picture the device holds: its bytes', () async {
    final p = await OwnProfile.load(
        readProfile: () async =>
            _json({'name': 'Joep', 'iconFile': 'did:ad:f'}),
        readBytes: (f) async =>
            f == 'did:ad:f' ? Uint8List.fromList([1]) : null);
    expect(p.imageBytes, [1]);
    expect(p.pendingImage, isFalse);
  });

  test('a File whose bytes have not arrived: pending, not an error', () async {
    for (final bytes in [null, Uint8List(0)]) {
      final p = await OwnProfile.load(
          readProfile: () async =>
              _json({'name': 'Joep', 'iconFile': 'did:ad:f'}),
          readBytes: (_) async => bytes,
          fetchBytes: (_) async => throw StateError('Status: 403'));
      expect(p.imageBytes, isNull);
      expect(p.pendingImage, isTrue);
    }
    final failing = await OwnProfile.load(
        readProfile: () async => _json({'iconFile': 'did:ad:f'}),
        readBytes: (_) async => throw StateError('store busy'),
        fetchBytes: (_) async => throw StateError('offline'));
    expect(failing.pendingImage, isTrue);
  });

  test('a File without bytes but with a download url: the url, not pending',
      () async {
    final p = await OwnProfile.load(
        readProfile: () async => _json({
              'iconFile': 'did:ad:f',
              'imageUrl': 'https://a.test/d/me.png',
            }),
        readBytes: (_) async => null,
        fetchBytes: (_) async => throw StateError('offline'));
    expect(p.imageUrl, 'https://a.test/d/me.png');
    expect(p.pendingImage, isFalse);
  });

  test('no picture, blank strings', () async {
    final p = await OwnProfile.load(
        readProfile: () async => _json({'name': ' ', 'imageUrl': ''}));
    expect(p.name, isNull);
    expect(p.imageUrl, isNull);
    expect(p.pendingImage, isFalse);
  });

  test('a picture on the server: fetched once, then kept for the session',
      () async {
    var fetches = 0;
    Future<Uint8List> fetch(String f) async {
      fetches++;
      expect(f, 'did:ad:f');
      return Uint8List.fromList([7, 7]);
    }

    Future<OwnProfile> load() => OwnProfile.load(
        readProfile: () async =>
            _json({'name': 'Joep', 'iconFile': 'did:ad:f'}),
        readBytes: (_) async => null,
        fetchBytes: fetch);
    final a = await load();
    expect(a.imageBytes, [7, 7]);
    expect(a.pendingImage, isFalse);
    final b = await load();
    expect(b.imageBytes, [7, 7]);
    expect(fetches, 1);
  });

  test('a failed fetch is pending, then tried again on the next load',
      () async {
    var fetches = 0;
    Future<OwnProfile> load() => OwnProfile.load(
        readProfile: () async => _json({'iconFile': 'did:ad:f'}),
        readBytes: (_) async => null,
        fetchBytes: (_) async {
          if (fetches++ == 0) throw StateError('Status: 403');
          return Uint8List.fromList([1, 2]);
        });
    final first = await load();
    expect(first.pendingImage, isTrue);
    expect(first.imageBytes, isNull);
    final second = await load();
    expect(second.imageBytes, [1, 2]);
    expect(fetches, 2);
  });

  test('a slow fetch does not hold the profile back, and lands for the next',
      () async {
    final gate = Completer<Uint8List>();
    var fetches = 0;
    Future<OwnProfile> load() => OwnProfile.load(
        readProfile: () async =>
            _json({'name': 'Joep', 'iconFile': 'did:ad:f'}),
        readBytes: (_) async => null,
        fetchWait: const Duration(milliseconds: 20),
        fetchBytes: (_) {
          fetches++;
          return gate.future;
        });
    final first = await load();
    expect(first.name, 'Joep');
    expect(first.pendingImage, isTrue);
    // Still running: asking again does not start another.
    await load();
    expect(fetches, 1);
    gate.complete(Uint8List.fromList([9]));
    await Future<void>.delayed(Duration.zero);
    expect((await load()).imageBytes, [9]);
    expect(fetches, 1);
  });
}
