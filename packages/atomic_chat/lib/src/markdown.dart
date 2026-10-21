/// A small Markdown parser for chat messages: the subset models write
/// (headings, emphasis, code, lists, quotes, links, tables, rules). It never
/// fails: what it does not understand stays text, and a message cut off while
/// it streams (an open code fence, a `**` without its pair) still reads well.
///
/// [MarkdownDocument] parses incrementally: text that grows at its end
/// re-parses only its last block, so a streaming answer costs little per
/// update.
library;

/// One block of a message.
sealed class MdBlock {
  const MdBlock();
}

class MdHeading extends MdBlock {
  final int level;
  final String text;
  const MdHeading(this.level, this.text);
}

class MdParagraph extends MdBlock {
  /// Lines joined by `\n`: a line break in a chat message is meant.
  final String text;
  const MdParagraph(this.text);
}

class MdCode extends MdBlock {
  /// The info string's first word ('' when none).
  final String language;
  final String code;

  /// False while the closing fence has not arrived.
  final bool closed;
  const MdCode(this.language, this.code, {this.closed = true});
}

class MdList extends MdBlock {
  final bool ordered;
  final int start;
  final List<List<MdBlock>> items;
  const MdList({required this.ordered, this.start = 1, required this.items});
}

class MdQuote extends MdBlock {
  final List<MdBlock> children;
  const MdQuote(this.children);
}

enum MdAlign { left, center, right }

class MdTable extends MdBlock {
  final List<String> header;
  final List<MdAlign> aligns;
  final List<List<String>> rows;
  const MdTable(this.header, this.aligns, this.rows);
}

class MdRule extends MdBlock {
  const MdRule();
}

final _fence = RegExp(r'^ {0,3}(`{3,}|~{3,})\s*([^\s`]*)');
final _heading = RegExp(r'^ {0,3}(#{1,6})(?:\s+(.*?))?\s*$');
final _rule = RegExp(r'^ {0,3}([-*_])(?:[ \t]*\1){2,}[ \t]*$');
final _quote = RegExp(r'^ {0,3}> ?');
final _bullet = RegExp(r'^( *)([-*+])( +|$)');
final _ordered = RegExp(r'^( *)(\d{1,9})([.)])( +|$)');
final _tableSep = RegExp(r'^ *\|? *:?-+:? *(\| *:?-+:? *)*\|? *$');

String _expandTabs(String line) =>
    line.contains('\t') ? line.replaceAll('\t', '    ') : line;

int _indentOf(String line) {
  var i = 0;
  while (i < line.length && line.codeUnitAt(i) == 0x20) {
    i++;
  }
  return i;
}

bool _blank(String line) => line.trim().isEmpty;

/// A list marker at the start of [line]: its indent, the width up to the
/// item's text, whether it is ordered, its number.
({int indent, int content, bool ordered, int number, String mark})? _marker(
    String line) {
  final b = _bullet.firstMatch(line);
  if (b != null) {
    // `* * *` and `- - -` are rules, not items.
    if (_rule.hasMatch(line)) return null;
    final indent = b.group(1)!.length;
    final spaces = b.group(3)!.length;
    return (
      indent: indent,
      content: indent + 1 + (spaces == 0 || spaces > 4 ? 1 : spaces),
      ordered: false,
      number: 0,
      mark: b.group(2)!,
    );
  }
  final o = _ordered.firstMatch(line);
  if (o != null) {
    final indent = o.group(1)!.length;
    final digits = o.group(2)!.length;
    final spaces = o.group(4)!.length;
    return (
      indent: indent,
      content: indent + digits + 1 + (spaces == 0 || spaces > 4 ? 1 : spaces),
      ordered: true,
      number: int.parse(o.group(2)!),
      mark: o.group(3)!,
    );
  }
  return null;
}

/// Whether [line] starts a block other than a paragraph (so it ends one).
bool _startsBlock(String line) =>
    _fence.hasMatch(line) ||
    _heading.hasMatch(line) ||
    _rule.hasMatch(line) ||
    _quote.hasMatch(line) ||
    _marker(line) != null;

List<String> _splitCells(String line) {
  var s = line.trim();
  if (s.startsWith('|')) s = s.substring(1);
  if (s.endsWith('|') && !s.endsWith(r'\|')) s = s.substring(0, s.length - 1);
  final cells = <String>[];
  final cell = StringBuffer();
  var inCode = false;
  for (var i = 0; i < s.length; i++) {
    final ch = s[i];
    if (ch == r'\' && i + 1 < s.length && s[i + 1] == '|') {
      cell.write('|');
      i++;
    } else if (ch == '`') {
      inCode = !inCode;
      cell.write(ch);
    } else if (ch == '|' && !inCode) {
      cells.add(cell.toString().trim());
      cell.clear();
    } else {
      cell.write(ch);
    }
  }
  cells.add(cell.toString().trim());
  return cells;
}

/// A parsed block and the line it starts on (for incremental parsing).
typedef _Placed = ({MdBlock block, int line});

/// The blocks of [lines] (tabs expanded), each with its first line.
List<_Placed> _parse(List<String> lines) {
  final out = <_Placed>[];
  var i = 0;
  final n = lines.length;
  while (i < n) {
    final line = lines[i];
    if (_blank(line)) {
      i++;
      continue;
    }
    final start = i;

    final fence = _fence.firstMatch(line);
    if (fence != null) {
      final mark = fence.group(1)!;
      final indent = _indentOf(line);
      final code = <String>[];
      var closed = false;
      i++;
      while (i < n) {
        final l = lines[i];
        final t = l.trimLeft();
        if (t.startsWith(mark[0] * mark.length) &&
            t.replaceAll(mark[0], '').trim().isEmpty) {
          closed = true;
          i++;
          break;
        }
        final strip = _indentOf(l) < indent ? _indentOf(l) : indent;
        code.add(l.substring(strip));
        i++;
      }
      out.add((
        block: MdCode(fence.group(2)!, code.join('\n'), closed: closed),
        line: start,
      ));
      continue;
    }

    if (_rule.hasMatch(line)) {
      out.add((block: const MdRule(), line: start));
      i++;
      continue;
    }

    final heading = _heading.firstMatch(line);
    if (heading != null) {
      var text = heading.group(2) ?? '';
      // A closing run of #s is not part of the title.
      text = text.replaceFirst(RegExp(r'\s+#+$'), '');
      if (RegExp(r'^#+$').hasMatch(text)) text = '';
      out.add((block: MdHeading(heading.group(1)!.length, text), line: start));
      i++;
      continue;
    }

    if (_quote.hasMatch(line)) {
      final inner = <String>[];
      while (i < n && !_blank(lines[i])) {
        final l = lines[i];
        final q = _quote.firstMatch(l);
        if (q != null) {
          inner.add(l.substring(q.end));
        } else if (inner.isNotEmpty && !_startsBlock(l)) {
          // A lazy continuation of the quote's paragraph.
          inner.add(l);
        } else {
          break;
        }
        i++;
      }
      out.add((
        block: MdQuote([for (final p in _parse(inner)) p.block]),
        line: start,
      ));
      continue;
    }

    final marker = _marker(line);
    if (marker != null) {
      final items = <List<MdBlock>>[];
      final ordered = marker.ordered;
      final first = marker.number;
      var current = marker;
      while (i < n) {
        // One item: its first line, then what belongs to it.
        final itemLines = <String>[
          lines[i].substring(current.content > lines[i].length
              ? lines[i].length
              : current.content)
        ];
        i++;
        var sawBlank = false;
        while (i < n) {
          final l = lines[i];
          if (_blank(l)) {
            sawBlank = true;
            itemLines.add('');
            i++;
            continue;
          }
          final ind = _indentOf(l);
          final m = _marker(l);
          if (ind >= current.content ||
              (m != null && m.indent > current.indent)) {
            // Deeper: the item's own content (a nested list may be indented
            // less than the item's text, as models often write it).
            itemLines.add(
                l.substring(ind < current.content ? ind : current.content));
            sawBlank = false;
            i++;
            continue;
          }
          if (m != null) break;
          if (sawBlank || _startsBlock(l)) break;
          // A lazy continuation line of the item's paragraph.
          itemLines.add(l.trimLeft());
          i++;
        }
        while (itemLines.isNotEmpty && _blank(itemLines.last)) {
          itemLines.removeLast();
        }
        items.add([for (final p in _parse(itemLines)) p.block]);
        if (i >= n) break;
        final next = _marker(lines[i]);
        if (next == null || next.ordered != ordered) break;
        current = next;
      }
      out.add((
        block: MdList(ordered: ordered, start: first, items: items),
        line: start,
      ));
      continue;
    }

    if (line.contains('|') && i + 1 < n && _tableSep.hasMatch(lines[i + 1])) {
      final header = _splitCells(line);
      final aligns = [
        for (final s in _splitCells(lines[i + 1]))
          s.startsWith(':') && s.endsWith(':')
              ? MdAlign.center
              : s.endsWith(':')
                  ? MdAlign.right
                  : MdAlign.left,
      ];
      i += 2;
      final rows = <List<String>>[];
      while (i < n && !_blank(lines[i]) && lines[i].contains('|')) {
        rows.add(_splitCells(lines[i]));
        i++;
      }
      out.add((block: MdTable(header, aligns, rows), line: start));
      continue;
    }

    // A paragraph: up to a blank line or another block.
    final para = <String>[line.trim()];
    i++;
    while (i < n && !_blank(lines[i]) && !_startsBlock(lines[i])) {
      // A table under a line of text starts there.
      if (lines[i].contains('|') &&
          i + 1 < n &&
          _tableSep.hasMatch(lines[i + 1])) {
        break;
      }
      para.add(lines[i].trim());
      i++;
    }
    out.add((block: MdParagraph(para.join('\n')), line: start));
  }
  return out;
}

/// The blocks of [text].
List<MdBlock> parseMarkdown(String text) => [
      for (final p in _parse(
          [for (final l in text.split('\n')) _expandTabs(l.trimRight())]))
        p.block
    ];

/// A message's blocks, kept between updates: when the text only grew, the
/// blocks before the last one are kept as they were (the same objects), and
/// only the last is parsed again.
class MarkdownDocument {
  String _text = '';
  List<String> _lines = const [];
  List<_Placed> _placed = const [];

  List<MdBlock> get blocks => [for (final p in _placed) p.block];

  /// The blocks of [text]; cheap when [text] extends the previous one.
  List<MdBlock> update(String text) {
    if (text == _text && _placed.isNotEmpty) return blocks;
    final lines = [
      for (final l in text.split('\n')) _expandTabs(l.trimRight())
    ];
    if (_placed.length > 1 && text.startsWith(_text)) {
      // Everything up to the last block is settled: a block ends only on a
      // line after it, and those lines are unchanged.
      final keep = _placed.sublist(0, _placed.length - 1);
      final from = _placed.last.line;
      final tail = _parse(lines.sublist(from));
      _placed = [
        ...keep,
        for (final p in tail) (block: p.block, line: p.line + from),
      ];
    } else {
      _placed = _parse(lines);
    }
    _text = text;
    _lines = lines;
    return blocks;
  }

  /// The text's lines, as parsed.
  List<String> get lines => _lines;
}

// Inline -------------------------------------------------------------------

/// A run of inline content.
sealed class MdInline {
  const MdInline();
}

class MdText extends MdInline {
  final String text;
  const MdText(this.text);
}

class MdCodeSpan extends MdInline {
  final String code;
  const MdCodeSpan(this.code);
}

enum MdStyle { bold, italic, strike }

class MdStyled extends MdInline {
  final MdStyle style;
  final List<MdInline> children;
  const MdStyled(this.style, this.children);
}

class MdLink extends MdInline {
  final String url;
  final List<MdInline> children;

  /// An image (`![alt](url)`): shown as a link to it.
  final bool image;
  const MdLink(this.url, this.children, {this.image = false});
}

final _bareUrl =
    RegExp(r'(?:https?://|atomic:|did:ad:|mailto:)[^\s<>"`]*[^\s<>"`.,;:!?)\]}'
        "'"
        r']');
final _escapable = RegExp(r'''[\\`*_{}\[\]()#+\-.!|~<>"']''');

bool _isWord(String s, int i) =>
    i >= 0 && i < s.length && RegExp(r'[A-Za-z0-9]').hasMatch(s[i]);

bool _isSpace(String s, int i) => i < 0 || i >= s.length || s[i].trim().isEmpty;

/// The inline content of [text]. With [open], a marker without its closing
/// pair (`**bold`, `` `code ``) styles the rest of the text: a streaming
/// answer whose pair has not arrived yet.
List<MdInline> parseInline(String text, {bool open = false}) {
  final out = <MdInline>[];
  final buf = StringBuffer();
  void flush() {
    if (buf.isNotEmpty) {
      out.add(MdText(buf.toString()));
      buf.clear();
    }
  }

  final s = text;
  var i = 0;
  while (i < s.length) {
    final ch = s[i];

    if (ch == r'\' && i + 1 < s.length && _escapable.hasMatch(s[i + 1])) {
      buf.write(s[i + 1]);
      i += 2;
      continue;
    }

    if (ch == '`') {
      var run = 1;
      while (i + run < s.length && s[i + run] == '`') {
        run++;
      }
      final tick = '`' * run;
      final close = s.indexOf(tick, i + run);
      if (close >= 0) {
        flush();
        var code = s.substring(i + run, close);
        if (code.length > 1 && code.startsWith(' ') && code.endsWith(' ')) {
          code = code.substring(1, code.length - 1);
        }
        out.add(MdCodeSpan(code.replaceAll('\n', ' ')));
        i = close + run;
        continue;
      }
      if (open) {
        flush();
        out.add(MdCodeSpan(s.substring(i + run)));
        return out;
      }
      buf.write(tick);
      i += run;
      continue;
    }

    if ((ch == '*' || ch == '_' || ch == '~') &&
        i + 1 < s.length &&
        s[i + 1] == ch &&
        !_isSpace(s, i + 2)) {
      final delim = ch * 2;
      if (ch == '_' && _isWord(s, i - 1)) {
        buf.write(delim);
        i += 2;
        continue;
      }
      var close = s.indexOf(delim, i + 2);
      while (close >= 0 && _isSpace(s, close - 1)) {
        close = s.indexOf(delim, close + 1);
      }
      if (close >= 0 && close > i + 2) {
        flush();
        out.add(MdStyled(
          ch == '~' ? MdStyle.strike : MdStyle.bold,
          parseInline(s.substring(i + 2, close)),
        ));
        i = close + 2;
        continue;
      }
      if (open && close < 0 && ch != '~') {
        flush();
        out.add(MdStyled(MdStyle.bold, parseInline(s.substring(i + 2))));
        return out;
      }
      buf.write(delim);
      i += 2;
      continue;
    }

    if ((ch == '*' || ch == '_') && !_isSpace(s, i + 1)) {
      if (ch == '_' && _isWord(s, i - 1)) {
        buf.write(ch);
        i++;
        continue;
      }
      // The closing single marker: not part of a double one.
      var close = i + 1;
      int found = -1;
      while (true) {
        close = s.indexOf(ch, close);
        if (close < 0) break;
        final doubled = close + 1 < s.length && s[close + 1] == ch;
        if (doubled) {
          // Skip a nested bold pair.
          final end = s.indexOf(ch * 2, close + 2);
          if (end < 0) break;
          close = end + 2;
          continue;
        }
        if (!_isSpace(s, close - 1) && !(ch == '_' && _isWord(s, close + 1))) {
          found = close;
          break;
        }
        close++;
      }
      if (found > i + 1) {
        flush();
        out.add(
            MdStyled(MdStyle.italic, parseInline(s.substring(i + 1, found))));
        i = found + 1;
        continue;
      }
      buf.write(ch);
      i++;
      continue;
    }

    if (ch == '[' || (ch == '!' && i + 1 < s.length && s[i + 1] == '[')) {
      final image = ch == '!';
      final open0 = image ? i + 1 : i;
      final link = _linkAt(s, open0);
      if (link != null) {
        flush();
        out.add(MdLink(link.url, parseInline(link.label), image: image));
        i = link.end;
        continue;
      }
    }

    if (ch == '<') {
      final close = s.indexOf('>', i + 1);
      if (close > i + 1) {
        final inner = s.substring(i + 1, close);
        if (RegExp(r'^(https?://|atomic:|did:ad:|mailto:)\S+$')
            .hasMatch(inner)) {
          flush();
          out.add(MdLink(inner, [MdText(inner)]));
          i = close + 1;
          continue;
        }
      }
    }

    if ((ch == 'h' || ch == 'a' || ch == 'd' || ch == 'm') &&
        !_isWord(s, i - 1)) {
      final m = _bareUrl.matchAsPrefix(s, i);
      if (m != null) {
        flush();
        out.add(MdLink(m[0]!, [MdText(m[0]!)]));
        i = m.end;
        continue;
      }
    }

    buf.write(ch);
    i++;
  }
  flush();
  return out;
}

/// `[label](url)` starting at [at] (the `[`), or null.
({String label, String url, int end})? _linkAt(String s, int at) {
  var depth = 0;
  var j = at;
  for (; j < s.length; j++) {
    final c = s[j];
    if (c == r'\') {
      j++;
    } else if (c == '[') {
      depth++;
    } else if (c == ']') {
      depth--;
      if (depth == 0) break;
    }
  }
  if (j >= s.length || j + 1 >= s.length || s[j + 1] != '(') return null;
  var k = j + 2;
  var parens = 1;
  for (; k < s.length; k++) {
    if (s[k] == '(') parens++;
    if (s[k] == ')') {
      parens--;
      if (parens == 0) break;
    }
  }
  if (k >= s.length) return null;
  var target = s.substring(j + 2, k).trim();
  // `(url "title")`: the title is not shown.
  final space = target.indexOf(RegExp(r'\s'));
  if (space > 0) target = target.substring(0, space);
  if (target.startsWith('<') && target.endsWith('>')) {
    target = target.substring(1, target.length - 1);
  }
  return (label: s.substring(at + 1, j), url: target, end: k + 1);
}

/// The plain text of inline content (for a link without a label, a summary).
String inlinePlainText(List<MdInline> inlines) => [
      for (final n in inlines)
        switch (n) {
          MdText(:final text) => text,
          MdCodeSpan(:final code) => code,
          MdStyled(:final children) => inlinePlainText(children),
          MdLink(:final children) => inlinePlainText(children),
        }
    ].join();
