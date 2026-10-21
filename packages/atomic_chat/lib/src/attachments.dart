import 'dart:async';
import 'dart:typed_data';
import 'dart:ui' as ui;

import 'package:atomic_flutter/atomic_flutter.dart'
    show AppColors, AppColorsExt;
import 'package:flutter/material.dart';

import 'assistant_api.dart';
import 'chat_parts.dart';
import 'models.dart';
import 'resource_row.dart';

/// A file the person picked: its name, media type and bytes.
class PickedFile {
  final String name;
  final String mediaType;
  final Uint8List bytes;

  const PickedFile({
    required this.name,
    required this.mediaType,
    required this.bytes,
  });
}

/// How the chat gets photos and files from the device. The package has no
/// platform picker of its own: the host gives one ([defaultAttachmentPicker]
/// or `ChatScreen.attachmentPicker`); without one the chat attaches only
/// resources from the person's drives.
abstract class AttachmentPicker {
  const AttachmentPicker();

  /// Whether [pickImages] can be offered.
  bool get canPickImages => true;

  /// Whether [takePhoto] can be offered (the device has a camera and the
  /// picker can use it).
  bool get canTakePhoto => false;

  /// Photos from the device's library; empty when the person cancels.
  Future<List<PickedFile>> pickImages();

  /// A new photo from the camera; null when the person cancels.
  Future<PickedFile?> takePhoto() async => null;

  /// Files of any kind; empty when the person cancels.
  Future<List<PickedFile>> pickFiles();
}

/// The picker every chat uses unless given its own; set by the host.
AttachmentPicker? defaultAttachmentPicker;

/// The largest text file and image (before it is made smaller) attached.
const maxTextFileBytes = 200 * 1024;
const maxImageBytes = 15 * 1024 * 1024;

/// The longest side of an attached image, in pixels: larger ones are made
/// smaller before they are sent and stored.
const maxImageSide = 1280;

/// Why [file] cannot be attached; null when it can. [images] says whether
/// the AI looks at images.
String? attachmentProblem(PickedFile file, {required bool images}) {
  final image = file.mediaType.startsWith('image/');
  if (image) {
    if (!images) return "This AI can't see images.";
    if (file.bytes.length > maxImageBytes) return '${file.name} is too large.';
    return null;
  }
  if (!isTextMediaType(file.mediaType, file.name)) {
    return "Can't read ${file.name}: the AI reads text files and images.";
  }
  if (file.bytes.length > maxTextFileBytes) {
    return '${file.name} is too large (at most 200 KB of text).';
  }
  return null;
}

/// [file] as a message part: an image made at most [maxImageSide] wide (a
/// PNG then), any other file as it is.
Future<FilePart> attachmentPart(PickedFile file) async {
  var bytes = file.bytes;
  var type = file.mediaType;
  var name = file.name;
  if (type.startsWith('image/') && type != 'image/svg+xml') {
    final smaller = await _shrink(bytes);
    if (smaller != null) {
      bytes = smaller;
      type = 'image/png';
      final dot = name.lastIndexOf('.');
      name = '${dot > 0 ? name.substring(0, dot) : name}.png';
    }
  }
  return FilePart.bytes(bytes, mediaType: type, filename: name);
}

/// [bytes] at most [maxImageSide] wide and high, as a PNG; null when the
/// image is small enough already or cannot be read.
Future<Uint8List?> _shrink(Uint8List bytes) async {
  try {
    final buffer = await ui.ImmutableBuffer.fromUint8List(bytes);
    final descriptor = await ui.ImageDescriptor.encoded(buffer);
    final w = descriptor.width, h = descriptor.height;
    if (w <= maxImageSide && h <= maxImageSide) {
      descriptor.dispose();
      buffer.dispose();
      return null;
    }
    final scale = maxImageSide / (w > h ? w : h);
    final codec = await descriptor.instantiateCodec(
      targetWidth: (w * scale).round(),
      targetHeight: (h * scale).round(),
    );
    final frame = await codec.getNextFrame();
    final data = await frame.image.toByteData(format: ui.ImageByteFormat.png);
    frame.image.dispose();
    codec.dispose();
    return data?.buffer.asUint8List();
  } catch (_) {
    return null;
  }
}

/// What the attach button offers.
enum AttachChoice { photos, camera, file, drive }

/// The attach sheet: photos, the camera, a file, or a resource from the
/// person's drives. A choice the device or the AI cannot do is shown
/// switched off, with why.
Future<AttachChoice?> showAttachSheet(
  BuildContext context, {
  required AttachmentPicker? picker,
  required bool images,
}) {
  final c = context.appColors;
  const noPicker = 'Not available in this app yet';
  const noImages = 'The included AI reads text only';
  Widget tile(AttachChoice choice, IconData icon, String title,
          {String? off}) =>
      ListTile(
        key: Key('attach-${choice.name}'),
        leading: Icon(icon, color: off == null ? c.main : c.textSecondary),
        title: Text(title),
        subtitle: off == null ? null : Text(off),
        enabled: off == null,
        onTap: () => Navigator.pop(context, choice),
      );
  return showModalBottomSheet<AttachChoice>(
    context: context,
    showDragHandle: true,
    builder: (context) => SafeArea(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          tile(
            AttachChoice.photos,
            Icons.photo_library_outlined,
            'Photo library',
            off: picker == null || !picker.canPickImages
                ? noPicker
                : images
                    ? null
                    : noImages,
          ),
          tile(
            AttachChoice.camera,
            Icons.photo_camera_outlined,
            'Camera',
            off: picker == null || !picker.canTakePhoto
                ? noPicker
                : images
                    ? null
                    : noImages,
          ),
          tile(
            AttachChoice.file,
            Icons.attach_file,
            'File',
            off: picker == null ? noPicker : null,
          ),
          tile(AttachChoice.drive, Icons.folder_outlined, 'From my drive'),
          const SizedBox(height: 8),
        ],
      ),
    ),
  );
}

/// A resource from the person's drives: search, or one opened lately.
Future<ContextResource?> showDrivePicker(
  BuildContext context, {
  required AssistantApi api,
  required List<RecentResource> recent,
}) =>
    showModalBottomSheet<ContextResource>(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (_) => _DrivePicker(api: api, recent: recent),
    );

class _DrivePicker extends StatefulWidget {
  final AssistantApi api;
  final List<RecentResource> recent;

  const _DrivePicker({required this.api, required this.recent});

  @override
  State<_DrivePicker> createState() => _DrivePickerState();
}

class _DrivePickerState extends State<_DrivePicker> {
  Timer? _debounce;
  String _query = '';
  List<SearchHit>? _hits;
  int _asked = 0;

  @override
  void dispose() {
    _debounce?.cancel();
    super.dispose();
  }

  void _changed(String q) {
    _debounce?.cancel();
    setState(() => _query = q.trim());
    if (_query.isEmpty) return setState(() => _hits = null);
    _debounce = Timer(const Duration(milliseconds: 250), () async {
      final asked = ++_asked;
      List<SearchHit> hits;
      try {
        hits = await widget.api.search(_query);
      } catch (_) {
        hits = const [];
      }
      if (mounted && asked == _asked) setState(() => _hits = hits);
    });
  }

  void _pick(String subject, String title, String className, String? emoji) =>
      Navigator.pop<ContextResource>(context, (
        subject: subject,
        title: title.isEmpty ? 'Untitled' : title,
        className: className,
        emoji: emoji,
      ));

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final hits = _hits;
    final rows = <Widget>[
      if (_query.isEmpty) ...[
        if (widget.recent.isNotEmpty) _heading(c, 'Recent'),
        for (final r in widget.recent)
          ResourceRow(
            emoji: r.emoji,
            icon: iconForClass(r.className),
            title: r.title.isEmpty ? 'Untitled' : r.title,
            detail: classLabel(r.className),
            onTap: () => _pick(r.subject, r.title, r.className, r.emoji),
          ),
      ] else if (hits == null)
        const Padding(
          padding: EdgeInsets.all(24),
          child: Center(child: CircularProgressIndicator()),
        )
      else if (hits.isEmpty)
        Padding(
          padding: const EdgeInsets.all(24),
          child: Text('Nothing found',
              textAlign: TextAlign.center,
              style: TextStyle(color: c.textSecondary)),
        )
      else
        for (final h in hits)
          ResourceRow(
            emoji: h.emoji,
            icon: iconForClass(h.className),
            title: h.title.isEmpty ? 'Untitled' : h.title,
            detail: classLabel(h.className),
            onTap: () => _pick(h.subject, h.title, h.className, h.emoji),
          ),
    ];
    return Padding(
      padding: EdgeInsets.only(bottom: MediaQuery.viewInsetsOf(context).bottom),
      child: SizedBox(
        height: MediaQuery.sizeOf(context).height * 0.7,
        child: Column(
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
              child: TextField(
                key: const Key('drive-picker-search'),
                autofocus: widget.recent.isEmpty,
                onChanged: _changed,
                decoration: InputDecoration(
                  hintText: 'Search your drives',
                  prefixIcon: const Icon(Icons.search),
                  filled: true,
                  fillColor: c.bg1,
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(9),
                    borderSide: BorderSide.none,
                  ),
                ),
              ),
            ),
            Expanded(child: ListView(children: rows)),
          ],
        ),
      ),
    );
  }

  Widget _heading(AppColors c, String text) => Padding(
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
        child:
            Text(text, style: TextStyle(color: c.textSecondary, fontSize: 12)),
      );
}

/// An attached image, small.
class AttachmentThumb extends StatelessWidget {
  final FilePart part;
  final double size;

  const AttachmentThumb(this.part, {super.key, this.size = 56});

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final bytes = part.bytes;
    return ClipRRect(
      borderRadius: BorderRadius.circular(8),
      child: Container(
        width: size,
        height: size,
        color: c.bg1,
        child: bytes == null
            ? Icon(Icons.image_outlined, color: c.textSecondary)
            : Image.memory(
                bytes,
                fit: BoxFit.cover,
                cacheWidth:
                    (size * MediaQuery.devicePixelRatioOf(context)).round(),
                gaplessPlayback: true,
                errorBuilder: (_, __, ___) =>
                    Icon(Icons.broken_image_outlined, color: c.textSecondary),
              ),
      ),
    );
  }
}

/// A small chip for an attached file or resource; removable when
/// [onRemove] is given.
class AttachmentChip extends StatelessWidget {
  final IconData icon;
  final String? emoji;
  final String label;
  final VoidCallback? onRemove;
  final VoidCallback? onTap;

  /// On a message of the person's own (the chip takes that bubble's colours).
  final bool onMine;

  const AttachmentChip({
    super.key,
    required this.icon,
    this.emoji,
    required this.label,
    this.onRemove,
    this.onTap,
    this.onMine = false,
  });

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final fg = onMine ? c.mainSelectedFg : c.textPrimary;
    final shown = label.length > 28 ? '${label.substring(0, 27)}…' : label;
    return Material(
      color: onMine ? c.main.withValues(alpha: 0.10) : c.bg1,
      shape: StadiumBorder(side: BorderSide(color: c.border)),
      child: InkWell(
        customBorder: const StadiumBorder(),
        onTap: onTap,
        child: Padding(
          padding: EdgeInsets.fromLTRB(10, 4, onRemove == null ? 12 : 4, 4),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              emoji != null
                  ? Text(emoji!, style: const TextStyle(fontSize: 13))
                  : Icon(icon, size: 15, color: fg),
              const SizedBox(width: 6),
              Flexible(
                child: Text(
                  shown,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(fontSize: 12.5, color: fg),
                ),
              ),
              if (onRemove != null)
                InkResponse(
                  onTap: onRemove,
                  radius: 14,
                  child: Padding(
                    padding: const EdgeInsets.all(3),
                    child: Icon(Icons.close,
                        size: 14,
                        semanticLabel: 'Remove $label',
                        color: c.textSecondary),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }
}
