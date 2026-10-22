import 'package:atomic_chat/atomic_chat.dart';
import 'package:file_selector/file_selector.dart';

/// Photos and files for the AI chat, through the system's document picker
/// (`file_selector`): on Android the system picker (Photos among its
/// sources), on iOS the Files picker. There is no camera: taking a photo
/// needs a camera plugin, which the app does not have.
class FileSelectorAttachmentPicker extends AttachmentPicker {
  const FileSelectorAttachmentPicker();

  static const _images = XTypeGroup(
    label: 'Images',
    extensions: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'heic', 'heif'],
    mimeTypes: ['image/*'],
    uniformTypeIdentifiers: ['public.image'],
  );

  @override
  Future<List<PickedFile>> pickImages() async =>
      _read(await openFiles(acceptedTypeGroups: const [_images]));

  @override
  Future<List<PickedFile>> pickFiles() async => _read(await openFiles());

  static Future<List<PickedFile>> _read(List<XFile> files) async => [
        for (final f in files)
          PickedFile(
            name: f.name,
            mediaType: f.mimeType ?? mediaTypeOf(f.name),
            bytes: await f.readAsBytes(),
          ),
      ];
}

/// The media type of a file by its name's extension; a generic binary type
/// when unknown.
String mediaTypeOf(String name) {
  final dot = name.lastIndexOf('.');
  final ext = dot < 0 ? '' : name.substring(dot + 1).toLowerCase();
  return switch (ext) {
    'jpg' || 'jpeg' => 'image/jpeg',
    'png' => 'image/png',
    'gif' => 'image/gif',
    'webp' => 'image/webp',
    'heic' => 'image/heic',
    'heif' => 'image/heif',
    'svg' => 'image/svg+xml',
    'txt' || 'log' => 'text/plain',
    'md' || 'markdown' => 'text/markdown',
    'csv' => 'text/csv',
    'html' || 'htm' => 'text/html',
    'json' => 'application/json',
    'xml' => 'application/xml',
    'yaml' || 'yml' => 'application/yaml',
    'pdf' => 'application/pdf',
    _ => 'application/octet-stream',
  };
}
