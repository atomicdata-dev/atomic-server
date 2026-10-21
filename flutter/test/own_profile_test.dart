import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';

import 'package:atomic_app/atomic/own_profile.dart';

String _json(Map<String, Object?> m) => jsonEncode(m);

void main() {
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
          readBytes: (_) async => bytes);
      expect(p.imageBytes, isNull);
      expect(p.pendingImage, isTrue);
    }
    final failing = await OwnProfile.load(
        readProfile: () async => _json({'iconFile': 'did:ad:f'}),
        readBytes: (_) async => throw StateError('store busy'));
    expect(failing.pendingImage, isTrue);
  });

  test('a File without bytes but with a download url: the url, not pending',
      () async {
    final p = await OwnProfile.load(
        readProfile: () async => _json({
              'iconFile': 'did:ad:f',
              'imageUrl': 'https://a.test/d/me.png',
            }),
        readBytes: (_) async => null);
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
}
