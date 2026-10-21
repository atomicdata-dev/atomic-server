import 'package:atomic_flutter/atomic_flutter.dart'
    show AppColors, AppColorsExt;
import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'markdown.dart';

/// Opens a link of a message: a web address, or a resource (`atomic:` /
/// `did:ad:`).
typedef MarkdownLinkHandler = void Function(String url);

const _mono = 'monospace';
const _monoFallback = ['Menlo', 'Courier New', 'Courier'];

/// A chat message written in Markdown: headings, emphasis, code (blocks with
/// their language and a copy button), lists, quotes, links, tables and rules,
/// in the app's colours. The text can be selected across blocks.
///
/// While [streaming], a pair that has not arrived yet (`**`, a backtick)
/// styles the rest of the last block, and the parse of the text before it is
/// kept between updates: a growing answer re-parses only its last block, and
/// the widgets of the blocks before it are reused as they were.
///
/// [inline] reads only emphasis, code spans and links, line by line: what a
/// person types (a `# ` or `1. ` they wrote stays as written).
class MarkdownView extends StatefulWidget {
  final String text;
  final TextStyle? style;
  final bool streaming;
  final bool inline;
  final MarkdownLinkHandler? onLink;

  /// Wraps the blocks in a [SelectionArea]; off when an ancestor has one.
  final bool selectable;

  const MarkdownView(
    this.text, {
    super.key,
    this.style,
    this.streaming = false,
    this.inline = false,
    this.onLink,
    this.selectable = true,
  });

  @override
  State<MarkdownView> createState() => _MarkdownViewState();
}

class _MarkdownViewState extends State<MarkdownView> {
  final _doc = MarkdownDocument();

  /// The widget of each block, by the block object: kept blocks keep theirs.
  final Map<MdBlock, Widget> _built = {};
  Object? _builtFor;

  @override
  Widget build(BuildContext context) {
    final c = context.appColors;
    final base = DefaultTextStyle.of(context)
        .style
        .merge(TextStyle(color: c.textPrimary, height: 1.4))
        .merge(widget.style);
    // Theme, text scale and style decide every block's look.
    final key = (
      c,
      base,
      MediaQuery.textScalerOf(context),
      widget.onLink,
      widget.streaming
    );
    if (key != _builtFor) {
      _built.clear();
      _builtFor = key;
    }
    final r = _Renderer(c, base, widget.onLink,
        scale: MediaQuery.textScalerOf(context).scale(1));
    Widget body;
    if (widget.inline) {
      body = _Inline(
        parseInline(widget.text),
        style: base,
        renderer: r,
      );
    } else {
      // A finished message's parse is shared through a small cache: a row
      // scrolled out of a long chat and back is not parsed again.
      final blocks = widget.streaming
          ? _doc.update(widget.text)
          : _parsed(widget.text).blocks;
      final live = blocks.toSet();
      _built.removeWhere((b, _) => !live.contains(b));
      final children = <Widget>[];
      for (var i = 0; i < blocks.length; i++) {
        final last = i == blocks.length - 1;
        final b = blocks[i];
        // The last block of a streaming answer changes; it is not kept.
        final w = last && widget.streaming
            ? r.block(b, open: true)
            : _built.putIfAbsent(b, () => r.block(b));
        if (i > 0) children.add(SizedBox(height: r.gapBefore(b)));
        children.add(w);
      }
      body = Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: children,
      );
    }
    body = DefaultTextStyle(style: base, child: body);
    return widget.selectable ? SelectionArea(child: body) : body;
  }
}

/// Parses of finished messages, the most recently used last.
final _parseCache = <String, MarkdownDocument>{};
const _parseCacheSize = 256;

MarkdownDocument _parsed(String text) {
  final hit = _parseCache.remove(text);
  final doc = hit ?? (MarkdownDocument()..update(text));
  _parseCache[text] = doc;
  if (_parseCache.length > _parseCacheSize) {
    _parseCache.remove(_parseCache.keys.first);
  }
  return doc;
}

/// Builds the widgets of blocks.
class _Renderer {
  final AppColors c;
  final TextStyle base;
  final MarkdownLinkHandler? onLink;

  /// The text scale: room for list numbers grows with the text.
  final double scale;

  _Renderer(this.c, this.base, this.onLink, {this.scale = 1});

  double get _size => base.fontSize ?? 16;

  double gapBefore(MdBlock b) => switch (b) {
        MdHeading() => _size * 0.9,
        _ => _size * 0.6,
      };

  Widget blocks(List<MdBlock> list) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          for (var i = 0; i < list.length; i++) ...[
            if (i > 0) SizedBox(height: gapBefore(list[i]) * 0.6),
            block(list[i]),
          ],
        ],
      );

  Widget block(MdBlock b, {bool open = false}) => switch (b) {
        MdParagraph(:final text) =>
          _Inline(parseInline(text, open: open), style: base, renderer: this),
        MdHeading(:final level, :final text) => _Inline(
            parseInline(text, open: open),
            style: base.copyWith(
              fontSize: _size *
                  switch (level) {
                    1 => 22 / 16,
                    2 => 20 / 16,
                    3 => 18 / 16,
                    _ => 1.0,
                  },
              fontWeight: FontWeight.w700,
              height: 1.3,
            ),
            renderer: this,
          ),
        MdCode() => _CodeBlock(b, colors: c, style: base),
        MdRule() => Divider(height: 1, thickness: 1, color: c.border),
        MdQuote(:final children) => Container(
            padding: const EdgeInsets.only(left: 10),
            decoration: BoxDecoration(
              border: Border(left: BorderSide(color: c.bg2, width: 3)),
            ),
            child: DefaultTextStyle.merge(
              style: TextStyle(color: c.textSecondary),
              child: _Renderer(
                c,
                base.copyWith(color: c.textSecondary),
                onLink,
                scale: scale,
              ).blocks(children),
            ),
          ),
        MdList() => _list(b, 0),
        MdTable() => _table(b),
      };

  Widget _list(MdList list, int depth) {
    final marks = ['•', '◦', '▪'];
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        for (var i = 0; i < list.items.length; i++)
          Padding(
            padding: EdgeInsets.only(top: i == 0 ? 0 : _size * 0.25),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                SizedBox(
                  width: (list.ordered ? _size * 1.9 : _size * 1.3) * scale,
                  child: Text(
                    list.ordered
                        ? '${list.start + i}.'
                        : marks[depth % marks.length],
                    textAlign:
                        list.ordered ? TextAlign.right : TextAlign.center,
                    style: base.copyWith(
                      color: list.ordered ? c.textSecondary : c.textPrimary,
                      fontFeatures: const [FontFeature.tabularFigures()],
                    ),
                  ),
                ),
                SizedBox(width: _size * 0.4),
                Expanded(child: _item(list.items[i], depth)),
              ],
            ),
          ),
      ],
    );
  }

  Widget _item(List<MdBlock> item, int depth) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          for (var i = 0; i < item.length; i++) ...[
            if (i > 0) SizedBox(height: _size * 0.3),
            item[i] is MdList
                ? _list(item[i] as MdList, depth + 1)
                : block(item[i]),
          ],
        ],
      );

  Widget _table(MdTable t) {
    final columns = [t.header.length, for (final r in t.rows) r.length]
        .reduce((a, b) => a > b ? a : b);
    TextAlign align(int i) =>
        switch (i < t.aligns.length ? t.aligns[i] : MdAlign.left) {
          MdAlign.left => TextAlign.left,
          MdAlign.center => TextAlign.center,
          MdAlign.right => TextAlign.right,
        };
    TableRow row(List<String> cells, {bool head = false}) => TableRow(
          decoration: head
              ? BoxDecoration(color: c.bgBody.withValues(alpha: 0.5))
              : null,
          children: [
            for (var i = 0; i < columns; i++)
              Padding(
                padding:
                    const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                child: ConstrainedBox(
                  constraints: BoxConstraints(maxWidth: _size * 18),
                  child: _Inline(
                    parseInline(i < cells.length ? cells[i] : ''),
                    style: head
                        ? base.copyWith(fontWeight: FontWeight.w600)
                        : base,
                    renderer: this,
                    align: align(i),
                  ),
                ),
              ),
          ],
        );
    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      child: Table(
        defaultColumnWidth: const IntrinsicColumnWidth(),
        border: TableBorder.all(
          color: c.border,
          borderRadius: BorderRadius.circular(6),
        ),
        children: [
          row(t.header, head: true),
          for (final r in t.rows) row(r),
        ],
      ),
    );
  }

  /// The spans of inline content; links get a recognizer from [tap], on
  /// each of their pieces (a tap lands on the innermost span).
  InlineSpan span(
    MdInline n,
    TextStyle style,
    TapGestureRecognizer Function(String url) tap, [
    TapGestureRecognizer? link,
  ]) =>
      switch (n) {
        MdText(:final text) => TextSpan(text: text, recognizer: link),
        MdCodeSpan(:final code) => TextSpan(
            text: code,
            recognizer: link,
            style: style.copyWith(
              fontFamily: _mono,
              fontFamilyFallback: _monoFallback,
              fontSize: (style.fontSize ?? 16) * 0.92,
              backgroundColor: c.bg2.withValues(alpha: 0.35),
            ),
          ),
        MdStyled(style: final kind, :final children) => TextSpan(
            style: switch (kind) {
              MdStyle.bold => const TextStyle(fontWeight: FontWeight.w700),
              MdStyle.italic => const TextStyle(fontStyle: FontStyle.italic),
              MdStyle.strike =>
                const TextStyle(decoration: TextDecoration.lineThrough),
            },
            children: [for (final k in children) span(k, style, tap, link)],
          ),
        MdLink(:final url, :final children, :final image) => () {
            final r = onLink == null ? null : tap(url);
            return TextSpan(
              style: TextStyle(
                color: c.main,
                decoration: TextDecoration.underline,
                decorationColor: c.main.withValues(alpha: 0.5),
              ),
              children: [
                if (image) TextSpan(text: '🖼 ', recognizer: r),
                if (children.isEmpty)
                  TextSpan(text: url, recognizer: r)
                else
                  for (final k in children) span(k, style, tap, r),
              ],
            );
          }(),
      };
}

/// One run of inline content as rich text; owns the recognizers of its links.
class _Inline extends StatefulWidget {
  final List<MdInline> inlines;
  final TextStyle style;
  final _Renderer renderer;
  final TextAlign align;

  const _Inline(
    this.inlines, {
    required this.style,
    required this.renderer,
    this.align = TextAlign.start,
  });

  @override
  State<_Inline> createState() => _InlineState();
}

class _InlineState extends State<_Inline> {
  final List<TapGestureRecognizer> _taps = [];

  void _clear() {
    for (final t in _taps) {
      t.dispose();
    }
    _taps.clear();
  }

  @override
  void dispose() {
    _clear();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    _clear();
    TapGestureRecognizer tap(String url) {
      final t = TapGestureRecognizer()
        ..onTap = () => widget.renderer.onLink?.call(url);
      _taps.add(t);
      return t;
    }

    return Text.rich(
      TextSpan(
        style: widget.style,
        children: [
          for (final n in widget.inlines)
            widget.renderer.span(n, widget.style, tap),
        ],
      ),
      textAlign: widget.align,
    );
  }
}

/// A fenced code block: its language and a copy button above the code, which
/// scrolls sideways instead of wrapping.
class _CodeBlock extends StatelessWidget {
  final MdCode code;
  final AppColors colors;
  final TextStyle style;

  const _CodeBlock(this.code, {required this.colors, required this.style});

  @override
  Widget build(BuildContext context) {
    final c = colors;
    final size = (style.fontSize ?? 16) * 0.88;
    return Container(
      width: double.infinity,
      decoration: BoxDecoration(
        color: c.surface,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: c.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          Padding(
            padding: const EdgeInsets.only(left: 12, right: 2),
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    code.language.isEmpty ? 'code' : code.language,
                    style: TextStyle(
                      color: c.textSecondary,
                      fontSize: 12,
                      height: 1.2,
                    ),
                  ),
                ),
                _CopyButton(text: code.code, colors: c),
              ],
            ),
          ),
          Divider(height: 1, thickness: 1, color: c.border),
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            padding: const EdgeInsets.fromLTRB(12, 10, 12, 12),
            child: Text(
              code.code,
              softWrap: false,
              style: style.copyWith(
                fontFamily: _mono,
                fontFamilyFallback: _monoFallback,
                fontSize: size,
                height: 1.45,
                color: c.textPrimary,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _CopyButton extends StatefulWidget {
  final String text;
  final AppColors colors;

  const _CopyButton({required this.text, required this.colors});

  @override
  State<_CopyButton> createState() => _CopyButtonState();
}

class _CopyButtonState extends State<_CopyButton> {
  bool _copied = false;

  Future<void> _copy() async {
    await Clipboard.setData(ClipboardData(text: widget.text));
    if (!mounted) return;
    setState(() => _copied = true);
    await Future<void>.delayed(const Duration(milliseconds: 1500));
    if (mounted) setState(() => _copied = false);
  }

  @override
  Widget build(BuildContext context) => IconButton(
        tooltip: _copied ? 'Copied' : 'Copy code',
        visualDensity: VisualDensity.compact,
        iconSize: 16,
        color: _copied ? widget.colors.success : widget.colors.textSecondary,
        onPressed: _copy,
        icon: Icon(_copied ? Icons.check : Icons.copy_rounded),
      );
}
