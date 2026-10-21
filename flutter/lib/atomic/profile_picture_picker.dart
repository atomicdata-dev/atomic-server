import 'package:atomic_flutter/atomic_flutter.dart' show ProfilePicture;
import 'package:file_selector/file_selector.dart';

import '../assistant/file_attachment_picker.dart' show mediaTypeOf;

const _images = XTypeGroup(
  label: 'Images',
  extensions: ['jpg', 'jpeg', 'png', 'gif', 'webp'],
  mimeTypes: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
  uniformTypeIdentifiers: ['public.image'],
);

/// The largest picture the profile takes (the host refuses more).
const maxProfilePictureBytes = 16 * 1024 * 1024;

/// Lets the person pick a picture from their photos or files (the system
/// picker; there is no camera plugin in the app). Null when they cancel.
/// Throws when the file is not an image or is too large.
Future<ProfilePicture?> pickProfileImage() async {
  final file = await openFile(acceptedTypeGroups: const [_images]);
  if (file == null) return null;
  final type = file.mimeType ?? mediaTypeOf(file.name);
  if (!type.startsWith('image/')) {
    throw StateError('Choose an image (JPEG, PNG, GIF or WebP)');
  }
  final length = await file.length();
  if (length > maxProfilePictureBytes) {
    throw StateError('That picture is larger than 16 MB');
  }
  return ProfilePicture(
      name: file.name, mimeType: type, bytes: await file.readAsBytes());
}
