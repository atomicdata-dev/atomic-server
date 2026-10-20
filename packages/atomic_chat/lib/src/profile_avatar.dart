import 'package:atomic_flutter/atomic_flutter.dart' show AppColorsExt;
import 'package:flutter/material.dart';

import 'models.dart';

/// The person's picture in a circle when they have one, else their emoji,
/// else their initial (else a person icon).
class ProfileAvatar extends StatelessWidget {
  final String? name;
  final double radius;

  /// The picture's URL.
  final String? imageUrl;
  final String? emoji;

  const ProfileAvatar(
      {super.key, this.name, this.radius = 16, this.imageUrl, this.emoji});

  factory ProfileAvatar.of(ProfileIdentity? who, {double radius = 16}) =>
      ProfileAvatar(
          name: who?.name,
          imageUrl: who?.imageUrl,
          emoji: who?.emoji,
          radius: radius);

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final trimmed = name?.trim() ?? '';
    final icon = emoji?.trim() ?? '';
    final Widget fallback = icon.isNotEmpty
        ? Text(icon, style: TextStyle(fontSize: radius))
        : trimmed.isEmpty
            ? Icon(Icons.person, size: radius * 1.1, color: c.mainSelectedFg)
            : Text(trimmed.characters.first.toUpperCase(),
                style: TextStyle(
                    color: c.mainSelectedFg,
                    fontWeight: FontWeight.w600,
                    fontSize: radius * 0.9));
    final url = imageUrl?.trim() ?? '';
    return CircleAvatar(
      radius: radius,
      backgroundColor: c.mainSelectedBg,
      child: url.isEmpty
          ? fallback
          : ClipOval(
              child: Image.network(
                url,
                width: radius * 2,
                height: radius * 2,
                fit: BoxFit.cover,
                // Offline, or a picture this device may not read.
                errorBuilder: (_, __, ___) => Center(child: fallback),
              ),
            ),
    );
  }
}
