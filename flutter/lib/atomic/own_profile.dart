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

  /// Reads the profile from the host. [readProfile] and [readBytes] are seams
  /// for tests. Throws when the profile cannot be read.
  static Future<OwnProfile> load({
    Future<String> Function()? readProfile,
    Future<Uint8List?> Function(String file)? readBytes,
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
