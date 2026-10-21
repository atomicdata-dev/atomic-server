import 'dart:async';
import 'dart:collection';
import 'dart:typed_data';

import 'package:atomic_flutter/atomic_flutter.dart' show AppColorsExt;
import 'package:flutter/material.dart';

import 'background_activity.dart';
import 'models.dart';
import 'profile_avatar.dart';

/// What a row's leading slot can show instead of its generic icon. The first
/// that applies wins: [bytes], the [file] (a File resource whose bytes the
/// host reads, see [RowPictures]), the [url], the [data] URI; the [emoji]
/// shows when there is no picture (and under one that is still loading).
class ImageSource {
  final Uint8List? bytes;
  final String? file;
  final String? url;
  final String? data;
  final String? emoji;

  /// The server a relative [url] is relative to.
  final String? baseUrl;

  const ImageSource(
      {this.bytes, this.file, this.url, this.data, this.emoji, this.baseUrl});
  const ImageSource.file(String this.file)
      : bytes = null,
        url = null,
        data = null,
        emoji = null,
        baseUrl = null;
  const ImageSource.url(String this.url)
      : bytes = null,
        file = null,
        data = null,
        emoji = null,
        baseUrl = null;
  const ImageSource.data(String this.data)
      : bytes = null,
        file = null,
        url = null,
        emoji = null,
        baseUrl = null;
  const ImageSource.emoji(String this.emoji)
      : bytes = null,
        file = null,
        url = null,
        data = null,
        baseUrl = null;

  /// A row's picture and its own emoji as one source; null when there is
  /// nothing to show.
  static ImageSource? of(ResourcePicture? picture, {String? emoji}) {
    final e = (emoji ?? picture?.emoji)?.trim();
    final src = ImageSource(
        file: picture?.file,
        url: picture?.url,
        emoji: e == null || e.isEmpty ? null : e);
    return src.isEmpty ? null : src;
  }

  bool get isEmpty =>
      (bytes == null || bytes!.isEmpty) &&
      file == null &&
      url == null &&
      data == null &&
      (emoji == null || emoji!.isEmpty);

  @override
  bool operator ==(Object other) =>
      other is ImageSource &&
      identical(other.bytes, bytes) &&
      other.file == file &&
      other.url == url &&
      other.data == data &&
      other.emoji == emoji &&
      other.baseUrl == baseUrl;

  @override
  int get hashCode =>
      Object.hash(identical(bytes, null), file, url, data, emoji, baseUrl);
}

/// The bytes of File pictures rows show, read lazily through the host
/// ([loader], set by the screens from `AssistantApi.fileBytes`) and kept in a
/// small in-memory LRU by File subject, so a list that rebuilds does not read
/// them again. Misses are remembered for a while, so a picture that has not
/// synced yet is not asked for on every rebuild.
class RowPictures {
  RowPictures._();

  static Future<Uint8List?> Function(String file)? loader;

  /// How many pictures are kept.
  static int capacity = 128;

  /// How long a missing picture is not asked for again.
  static Duration missTtl = const Duration(seconds: 20);

  static final LinkedHashMap<String, Uint8List> _bytes = LinkedHashMap();
  static final Map<String, DateTime> _missed = {};
  static final Map<String, Future<Uint8List?>> _inFlight = {};

  /// The bytes if they are here, and marks them as used.
  static Uint8List? peek(String file) {
    final b = _bytes.remove(file);
    if (b != null) _bytes[file] = b;
    return b;
  }

  /// True when asking the host is worthwhile: not here, not in flight, not
  /// missed lately.
  static bool shouldLoad(String file) {
    if (loader == null || _bytes.containsKey(file)) return false;
    final miss = _missed[file];
    return miss == null || DateTime.now().difference(miss) > missTtl;
  }

  static Future<Uint8List?> load(String file) {
    final known = peek(file);
    if (known != null) return Future.value(known);
    final load = loader;
    if (load == null) return Future.value(null);
    return _inFlight[file] ??= () async {
      final busy = BackgroundActivity.instance.begin('pictures');
      try {
        final b = await load(file);
        if (b != null && b.isNotEmpty) {
          _bytes[file] = b;
          _missed.remove(file);
          while (_bytes.length > capacity) {
            _bytes.remove(_bytes.keys.first);
          }
          return b;
        }
      } catch (e) {
        debugPrint('RowPictures: $file not read: $e');
      } finally {
        busy.end();
      }
      _missed[file] = DateTime.now();
      return null;
    }()
        .whenComplete(() {
      _inFlight.remove(file);
    });
  }

  /// Forget everything (tests, signing out).
  static void clear() {
    _bytes.clear();
    _missed.clear();
    _inFlight.clear();
  }
}

enum RowShape { circle, square }

/// A stable background for the initial of [name]: the same name always gets
/// the same colour. Dark enough for white text.
Color initialColor(String name) {
  var h = 0;
  for (final r in name.trim().toLowerCase().runes) {
    h = (h * 31 + r) & 0x7fffffff;
  }
  return HSLColor.fromAHSL(1, (h % 360).toDouble(), 0.45, 0.40).toColor();
}

/// The leading slot of a list row: [size] dp square (32 by default) holding
/// the row's own picture, else its emoji, else the generic icon. People and
/// chats are circles, resources rounded squares of 8 dp.
///
/// The picture of a File is read lazily, once the row has stayed built for a
/// moment (a row scrolled past quickly reads nothing), off the UI thread
/// through [RowPictures]; it is decoded at the size it is drawn and fades in
/// over the fallback, which stays when there is no picture or it cannot be
/// decoded.
class RowLeading extends StatefulWidget {
  final ImageSource? image;

  /// The name the initial comes from, with [showInitial].
  final String fallbackLabel;
  final IconData fallbackIcon;
  final double size;
  final RowShape shape;

  /// Fall back to the initial of [fallbackLabel] on a colour from its name
  /// (people) instead of the generic icon.
  final bool showInitial;

  /// How long the row stays built before its picture is read.
  final Duration debounce;

  const RowLeading({
    super.key,
    this.image,
    this.fallbackLabel = '',
    required this.fallbackIcon,
    this.size = 32,
    this.shape = RowShape.square,
    this.showInitial = false,
    this.debounce = const Duration(milliseconds: 120),
  });

  @override
  State<RowLeading> createState() => _RowLeadingState();
}

class _RowLeadingState extends State<RowLeading> {
  Timer? _timer;
  Uint8List? _loaded;
  String? _loadedFor;

  @override
  void initState() {
    super.initState();
    _schedule();
  }

  @override
  void didUpdateWidget(RowLeading old) {
    super.didUpdateWidget(old);
    if (old.image?.file != widget.image?.file) {
      _loaded = null;
      _loadedFor = null;
      _schedule();
    }
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  void _schedule() {
    _timer?.cancel();
    final file = widget.image?.file;
    if (file == null || widget.image?.bytes != null) return;
    final cached = RowPictures.peek(file);
    if (cached != null) {
      _loaded = cached;
      _loadedFor = file;
      return;
    }
    if (!RowPictures.shouldLoad(file)) return;
    _timer = Timer(widget.debounce, () async {
      final bytes = await RowPictures.load(file);
      if (!mounted || widget.image?.file != file || bytes == null) return;
      setState(() {
        _loaded = bytes;
        _loadedFor = file;
      });
    });
  }

  ImageProvider? _provider() {
    final img = widget.image;
    if (img == null) return null;
    final bytes = img.bytes;
    if (bytes != null && bytes.isNotEmpty) return MemoryImage(bytes);
    if (img.file != null && _loadedFor == img.file && _loaded != null) {
      return MemoryImage(_loaded!);
    }
    final url = resolveAvatarUrl(img.url, base: img.baseUrl);
    if (url.isNotEmpty) return defaultAvatarImage(url);
    final data = img.data;
    return data == null ? null : defaultAvatarImage(data);
  }

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final size = widget.size;
    final circle = widget.shape == RowShape.circle;
    final emoji = widget.image?.emoji?.trim() ?? '';
    final label = widget.fallbackLabel.trim();
    final initial = widget.showInitial && label.isNotEmpty;
    final provider = _provider();

    final Widget base;
    Color? background;
    if (emoji.isNotEmpty) {
      base = Text(emoji,
          key: const Key('resource-emoji'),
          style: TextStyle(fontSize: size * 0.62, height: 1));
    } else if (initial) {
      background = initialColor(label);
      base = Text(label.characters.first.toUpperCase(),
          key: const Key('row-initial'),
          style: TextStyle(
              color: Colors.white,
              fontWeight: FontWeight.w600,
              fontSize: size * 0.45,
              height: 1));
    } else {
      if (circle) background = c.mainSelectedBg;
      base = Icon(widget.fallbackIcon, size: 20, color: c.main);
    }
    final radius = BorderRadius.circular(circle ? size / 2 : 8);
    return SizedBox(
      width: size,
      height: size,
      child: DecoratedBox(
        decoration: BoxDecoration(color: background, borderRadius: radius),
        child: ClipRRect(
          borderRadius: radius,
          child: Stack(
            fit: StackFit.expand,
            alignment: Alignment.center,
            children: [
              Center(child: base),
              if (provider != null)
                Image(
                  key: const Key('row-picture'),
                  image: ResizeImage.resizeIfNeeded(
                      (size * MediaQuery.devicePixelRatioOf(context)).ceil(),
                      null,
                      provider),
                  width: size,
                  height: size,
                  fit: BoxFit.cover,
                  filterQuality: FilterQuality.medium,
                  excludeFromSemantics: true,
                  frameBuilder: (_, child, frame, sync) => sync
                      ? child
                      : AnimatedOpacity(
                          opacity: frame == null ? 0 : 1,
                          duration: const Duration(milliseconds: 150),
                          child: child),
                  errorBuilder: (_, error, ___) {
                    debugPrint('RowLeading: no picture ($error)');
                    return const SizedBox.shrink();
                  },
                ),
            ],
          ),
        ),
      ),
    );
  }
}
