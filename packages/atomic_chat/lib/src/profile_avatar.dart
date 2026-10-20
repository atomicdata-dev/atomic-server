import 'package:atomic_flutter/atomic_flutter.dart' show AppColorsExt;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import 'models.dart';

/// The image a picture URL names: a `data:` URI is decoded in place, an
/// http(s) URL is loaded (and cached) over the network. Anything else (a
/// relative URL nobody resolved, a `file:` or `blob:` URL, an empty string) is
/// no picture, so the avatar shows the initial.
typedef AvatarImageFactory = ImageProvider? Function(String url);

ImageProvider? defaultAvatarImage(String url) {
  final uri = Uri.tryParse(url);
  if (uri == null) return null;
  if (uri.scheme == 'data') {
    final data = uri.data;
    if (data == null) return null;
    final bytes = data.contentAsBytes();
    return bytes.isEmpty ? null : MemoryImage(bytes);
  }
  if ((uri.scheme == 'http' || uri.scheme == 'https') && uri.host.isNotEmpty) {
    return NetworkImage(url);
  }
  return null;
}

/// A picture URL as an absolute one: a relative URL (`/download/me.png`) is
/// resolved against the server's [base]; an absolute one stays as it is.
/// Empty when there is nothing to show.
String resolveAvatarUrl(String? url, {String? base}) {
  final u = url?.trim() ?? '';
  if (u.isEmpty) return '';
  final parsed = Uri.tryParse(u);
  if (parsed == null) return '';
  if (parsed.hasScheme) return u;
  final b = Uri.tryParse(base?.trim() ?? '');
  if (b == null || !b.hasScheme || b.host.isEmpty) return '';
  return b.resolveUri(parsed).toString();
}

/// The person's picture in a circle when they have one, else their emoji,
/// else their initial (else a person icon). The initial shows while the
/// picture loads and when it cannot be loaded (offline, not a decodable
/// image, an svg); the picture then fades in over it.
class ProfileAvatar extends StatelessWidget {
  final String? name;
  final double radius;

  /// The picture's URL (http(s), or a `data:` URI; relative ones are
  /// resolved against [baseUrl]).
  final String? imageUrl;

  /// The picture's bytes when the device holds the file; shown in preference
  /// to [imageUrl] (works offline, and for files a server only gives to
  /// signed requests).
  final Uint8List? imageBytes;
  final String? emoji;

  /// The server a relative [imageUrl] is relative to.
  final String? baseUrl;

  /// The circle's and the initial's colours; by default the main colour's
  /// tint.
  final Color? background;
  final Color? foreground;

  /// How a URL becomes an image; [defaultAvatarImage] by default. A seam for
  /// tests.
  final AvatarImageFactory imageFactory;

  const ProfileAvatar(
      {super.key,
      this.name,
      this.radius = 16,
      this.imageUrl,
      this.imageBytes,
      this.emoji,
      this.baseUrl,
      this.background,
      this.foreground,
      this.imageFactory = defaultAvatarImage});

  factory ProfileAvatar.of(ProfileIdentity? who,
          {double radius = 16,
          Color? background,
          Color? foreground,
          AvatarImageFactory imageFactory = defaultAvatarImage}) =>
      ProfileAvatar(
          name: who?.name,
          imageUrl: who?.imageUrl,
          imageBytes: who?.imageBytes,
          emoji: who?.emoji,
          radius: radius,
          background: background,
          foreground: foreground,
          imageFactory: imageFactory);

  ImageProvider? _provider() {
    final bytes = imageBytes;
    if (bytes != null && bytes.isNotEmpty) return MemoryImage(bytes);
    final url = resolveAvatarUrl(imageUrl, base: baseUrl);
    if (url.isEmpty) return null;
    return imageFactory(url);
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final trimmed = name?.trim() ?? '';
    final icon = emoji?.trim() ?? '';
    final Widget fallback = icon.isNotEmpty
        ? Text(icon, style: TextStyle(fontSize: radius))
        : trimmed.isEmpty
            ? Icon(Icons.person,
                size: radius * 1.1, color: foreground ?? c.mainSelectedFg)
            : Text(trimmed.characters.first.toUpperCase(),
                style: TextStyle(
                    color: foreground ?? c.mainSelectedFg,
                    fontWeight: FontWeight.w600,
                    fontSize: radius * 0.9));
    final provider = _provider();
    final Widget circle = CircleAvatar(
      radius: radius,
      backgroundColor: background ?? c.mainSelectedBg,
      child: provider == null
          ? fallback
          : Stack(
              fit: StackFit.expand,
              alignment: Alignment.center,
              children: [
                Center(child: fallback),
                ClipOval(
                  child: Image(
                    // Decoded at the size it is drawn, not at the photo's.
                    image: ResizeImage.resizeIfNeeded(
                        (radius * 2 * MediaQuery.devicePixelRatioOf(context))
                            .ceil(),
                        null,
                        provider),
                    width: radius * 2,
                    height: radius * 2,
                    fit: BoxFit.cover,
                    filterQuality: FilterQuality.medium,
                    excludeFromSemantics: true,
                    frameBuilder: (_, child, frame, sync) => sync
                        ? child
                        : AnimatedOpacity(
                            opacity: frame == null ? 0 : 1,
                            duration: const Duration(milliseconds: 150),
                            child: child),
                    // Offline, a picture this device may not read, or not an
                    // image Flutter decodes (an svg): the initial stays.
                    errorBuilder: (_, error, ___) {
                      debugPrint('ProfileAvatar: no picture ($error)');
                      return const SizedBox.shrink();
                    },
                  ),
                ),
              ],
            ),
    );
    return trimmed.isEmpty
        ? circle
        : Semantics(label: trimmed, image: true, child: circle);
  }
}
