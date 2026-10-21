import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';

import 'atomic_client.dart';

/// This device's agent's profile as the screens show it.
class OwnProfile {
  const OwnProfile(
      {this.name,
      this.description,
      this.emoji,
      this.imageUrl,
      this.imageBytes,
      this.pendingImage = false});

  final String? name;
  final String? description;
  final String? emoji;

  /// The picture's URL, when the profile has one a server serves.
  final String? imageUrl;

  /// The picture's bytes, when this device holds the picture's File (what the
  /// web app's pictures are: blobs without a download URL). Preferred over the
  /// URL: it works offline and for files only signed requests may read.
  final Uint8List? imageBytes;

  /// The profile has a picture (a File) that is not here yet.
  final bool pendingImage;

  /// Pictures fetched from a server this session, by File subject, so a
  /// profile loaded again (a retry, a resume) has them at once.
  static final Map<String, Uint8List> _fetched = {};

  /// Fetches running now, by File subject: one request per file at a time.
  static final Map<String, Future<Uint8List?>> _fetching = {};

  @visibleForTesting
  static void forgetFetched() {
    _fetched.clear();
    _fetching.clear();
  }

  static Future<Uint8List?> _fetch(
      String file, Future<Uint8List> Function(String file) fetch) {
    final known = _fetched[file];
    if (known != null) return Future.value(known);
    return _fetching[file] ??= () async {
      try {
        final bytes = await fetch(file);
        if (bytes.isEmpty) return null;
        return _fetched[file] = bytes;
      } catch (e) {
        // The reason carries the HTTP status (a private file answers 401/403,
        // a file the server lost 404).
        debugPrint('Profile picture $file not fetched: $e');
        return null;
      } finally {
        _fetching.remove(file);
      }
    }();
  }

  /// Reads the profile from the host. [readProfile], [readBytes] and
  /// [fetchBytes] are seams for tests. A picture this device does not hold
  /// (the web app's pictures live on the server, usually a SaaS drive) is
  /// fetched from the server; the profile waits at most [fetchWait] for it,
  /// so the name never waits on a slow network, and the fetch carries on
  /// meanwhile: the next load has the picture. Throws when the profile cannot
  /// be read.
  static Future<OwnProfile> load({
    Future<String> Function()? readProfile,
    Future<Uint8List?> Function(String file)? readBytes,
    Future<Uint8List> Function(String file)? fetchBytes,
    Duration fetchWait = const Duration(seconds: 3),
  }) async {
    final p = jsonDecode(await (readProfile ?? AtomicClient.getOwnProfile)())
        as Map<String, dynamic>;
    String? text(String key) {
      final v = (p[key] as String?)?.trim();
      return v == null || v.isEmpty ? null : v;
    }

    final url = text('imageUrl');
    final file = text('iconFile');
    Uint8List? bytes;
    if (file != null) {
      try {
        bytes = await (readBytes ?? AtomicClient.readFileBytes)(file);
      } catch (e) {
        debugPrint('Profile picture $file not read: $e');
      }
      if (bytes != null && bytes.isEmpty) bytes = null;
      bytes ??= await _fetch(file, fetchBytes ?? AtomicClient.fetchFileBytes)
          .timeout(fetchWait, onTimeout: () => null);
    }
    return OwnProfile(
      name: text('name'),
      description: text('description'),
      emoji: text('emoji'),
      imageUrl: url,
      imageBytes: bytes,
      pendingImage: file != null && bytes == null && url == null,
    );
  }
}
