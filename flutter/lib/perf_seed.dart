import 'dart:convert';
import 'dart:io';

import 'atomic/store_location.dart';
import 'dart:math' as math;

import 'package:atomic_flutter/atomic_flutter.dart' show Perf;
import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';

import 'atomic/atomic_client.dart';

/// Test data for `scripts/perf_android.sh`, in debug and profile builds only
/// (compiled out of a release build).
///
/// The script writes a number to `perf_seed` in the app's external files
/// directory (`/sdcard/Android/data/<package>/files/perf_seed`, which adb can
/// write without root); after sign-in the app makes that many documents and
/// folders in the active drive, opens each once (so Recents fills) and adds
/// three AI chats, then deletes the file.
///
/// A second file, `perf_seed_chats` with `N [scale]`, makes N AI chats full of
/// text (see [_seedChats]) for the stress run (`perf_android.sh
/// --seed-chats`).
Future<void> perfSeedIfAsked() async {
  if (kReleaseMode || kIsWeb || !Platform.isAndroid) return;
  await _seedDocuments();
  await _seedChats();
  await _seedLongChat();
}

/// One AI chat of N short messages (`perf_seed_long` with `N`): a chat as
/// long as a busy channel, for scrolling through history
/// (`perf_android.sh --seed-long N`). About 120 characters a message (one in
/// twenty a few paragraphs), the newest a minute ago, so the chat is first
/// on Home. Logs `[perf] perf seed long N`.
Future<void> _seedLongChat() async {
  final int count;
  try {
    final dir = await getExternalStorageDirectory();
    if (dir == null) return;
    final flag = File('${dir.path}/perf_seed_long');
    if (!flag.existsSync()) return;
    count = int.tryParse(flag.readAsStringSync().trim()) ?? 50000;
    flag.deleteSync();
  } catch (_) {
    return;
  }
  final corpus = _Corpus();
  final rng = _Rng(7);
  final watch = Stopwatch()..start();
  final last = DateTime.now().millisecondsSinceEpoch - 60000;
  var bytes = 0;
  final entries = <Map<String, Object>>[];
  for (var m = 0; m < count; m++) {
    final len = rng.below(20) == 0 ? rng.range(300, 1000) : rng.range(20, 160);
    final text = corpus.message(rng, len);
    bytes += text.length;
    entries.add({
      'role': m.isEven ? 'user' : 'assistant',
      'parts': [
        {'type': 'text', 'text': text}
      ],
      'c': last - (count - 1 - m) * 20000,
    });
  }
  await AtomicClient.importAiChat('Very long chat', jsonEncode(entries));
  final docs = storeInSupportDirectory
      ? await getApplicationSupportDirectory()
      : await getApplicationDocumentsDirectory();
  final store = File('${docs.path}/atomic.redb');
  final mb = store.existsSync() ? store.lengthSync() / 1e6 : 0;
  debugPrint('[perf] seeded long chat: $count messages, '
      '${(bytes / 1e6).toStringAsFixed(1)} MB text, store ${mb.toStringAsFixed(0)} MB');
  Perf.span('perf seed long $count', watch.elapsedMilliseconds);
}

Future<void> _seedDocuments() async {
  final File flag;
  final int count;
  try {
    final dir = await getExternalStorageDirectory();
    if (dir == null) return;
    flag = File('${dir.path}/perf_seed');
    if (!flag.existsSync()) return;
    count = int.tryParse(flag.readAsStringSync().trim()) ?? 30;
    flag.deleteSync();
  } catch (_) {
    return;
  }
  final drive = AtomicClient.getActiveDrive();
  if (drive == null) return;
  final watch = Stopwatch()..start();
  for (var i = 0; i < count; i++) {
    final folder = i % 3 == 2;
    final subject = await AtomicClient.createResourceOfClass(
      drive,
      folder
          ? 'https://atomicdata.dev/classes/Folder'
          : 'https://atomicdata.dev/classes/DocumentV2',
      folder ? 'Perf folder $i' : 'Perf document $i',
    );
    AtomicClient.noteResourceOpened(drive, subject);
  }
  for (var i = 0; i < 3; i++) {
    await AtomicClient.createAiChat('Perf chat $i');
  }
  Perf.span('perf seed $count', watch.elapsedMilliseconds);
}

/// N AI chats of 20-60 messages each (user 200-1500, assistant 1500-4000
/// characters, times `scale`), in English, Dutch, German, French and Spanish
/// prose with headings, lists and code: the data of the Rust stress test
/// (`lib/tests/stress_chats.rs`), generated the same way so the device and
/// the host numbers compare. Written with `importAiChat` (one commit per
/// chat page), then logs `[perf] perf seed chats N` and the store's size.
Future<void> _seedChats() async {
  final File flag;
  final int count;
  final double scale;
  try {
    final dir = await getExternalStorageDirectory();
    if (dir == null) return;
    flag = File('${dir.path}/perf_seed_chats');
    if (!flag.existsSync()) return;
    final parts = flag.readAsStringSync().trim().split(RegExp(r'\s+'));
    count = int.tryParse(parts[0]) ?? 1000;
    scale = parts.length > 1 ? double.tryParse(parts[1]) ?? 1.0 : 1.0;
    flag.deleteSync();
  } catch (_) {
    return;
  }
  final corpus = _Corpus();
  final rng = _Rng(42);
  final watch = Stopwatch()..start();
  var bytes = 0;
  var messages = 0;
  const base = 1750000000000;
  for (var c = 0; c < count; c++) {
    final n = rng.range(20, 60);
    final entries = <Map<String, Object>>[];
    for (var m = 0; m < n; m++) {
      final user = m.isEven;
      final len = user ? rng.range(200, 1500) : rng.range(1500, 4000);
      final text = corpus.message(rng, (len * scale).round());
      bytes += text.length;
      entries.add({
        'role': user ? 'user' : 'assistant',
        'parts': [
          {'type': 'text', 'text': text}
        ],
        'c': base + c * 3600000 + m * 30000,
      });
    }
    messages += n;
    await AtomicClient.importAiChat(corpus.title(rng), jsonEncode(entries));
    if (c % 100 == 99) {
      debugPrint('[perf] seeding chats: ${c + 1}/$count, '
          '${(bytes / 1e6).toStringAsFixed(1)} MB text, ${watch.elapsedMilliseconds} ms');
    }
  }
  final docs = storeInSupportDirectory
      ? await getApplicationSupportDirectory()
      : await getApplicationDocumentsDirectory();
  final store = File('${docs.path}/atomic.redb');
  final mb = store.existsSync() ? store.lengthSync() / 1e6 : 0;
  debugPrint('[perf] seeded $count chats, $messages messages, '
      '${(bytes / 1e6).toStringAsFixed(1)} MB text, store ${mb.toStringAsFixed(0)} MB');
  Perf.span('perf seed chats $count', watch.elapsedMilliseconds);
}

/// xorshift64*, as in the Rust test.
class _Rng {
  _Rng(this._s);
  int _s;
  int next() {
    _s ^= _s >>> 12;
    _s ^= _s << 25;
    _s ^= _s >>> 27;
    return _s * 0x2545F4914F6CDD1D;
  }

  int below(int n) => ((next() >>> 1) % (n < 1 ? 1 : n));
  int range(int lo, int hi) => lo + below(hi - lo + 1);
  T pick<T>(List<T> items) => items[below(items.length)];

  /// Index i with weight about 1/(i+1).
  int zipf(int n) {
    final u = (next() >>> 11) / 9007199254740992.0;
    return (math.pow(n + 1.0, u) - 1).floor() % n;
  }
}

const _en = [
  'the', 'of', 'and', 'to', 'in', 'is', 'that', 'for', 'it', 'as', 'with', //
  'be', 'on', 'not', 'this', 'but', 'by', 'from', 'they', 'we', 'you', 'can',
  'will', 'which', 'would', 'there', 'what', 'about', 'when', 'make', 'like',
  'time', 'just', 'know', 'take', 'people', 'into', 'year', 'good', 'some',
  'could', 'see', 'other', 'than', 'then', 'now', 'look', 'only', 'come',
  'over', 'think', 'also', 'back', 'after', 'use', 'work', 'first', 'well',
  'way', 'new', 'want', 'because', 'budget', 'recipe', 'travel', 'garden',
  'invoice', 'meeting', 'project', 'server', 'database', 'kubernetes',
  'deployment', 'migration', 'schema', 'frontend', 'backend', 'latency',
  'throughput', 'memory', 'search', 'index', 'query', 'cache', 'summary',
  'proposal', 'strategy', 'customer', 'contract', 'holiday', 'bicycle',
  'kitchen', 'weather', 'mountain', 'library', 'history', 'physics',
  'chemistry', 'guitar', 'marathon',
];
const _nl = [
  'de', 'het', 'een', 'en', 'van', 'ik', 'te', 'dat', 'die', 'in', 'is', //
  'niet', 'op', 'aan', 'met', 'als', 'voor', 'maar', 'om', 'ook', 'nog',
  'wel', 'naar', 'dan', 'kan', 'zijn', 'bij', 'wordt', 'moet', 'hebben',
  'gemeente', 'fiets', 'boodschappen', 'vergadering', 'begroting',
  'afspraak', 'verjaardag', 'huiswerk', 'zomervakantie', 'belasting',
  'verzekering', 'aanvraag', 'onderzoek', 'samenvatting', 'gezondheid',
];
const _de = [
  'der', 'die', 'und', 'in', 'den', 'von', 'zu', 'das', 'mit', 'sich', //
  'auf', 'für', 'ist', 'nicht', 'ein', 'eine', 'als', 'auch', 'werden',
  'Rechnung', 'Wohnung', 'Steuererklärung', 'Krankenversicherung',
  'Bahnhof', 'Wanderung', 'Zusammenfassung', 'Anleitung', 'Überweisung',
];
const _fr = [
  'le', 'la', 'les', 'de', 'des', 'et', 'un', 'une', 'du', 'en', 'est', //
  'que', 'pour', 'dans', 'qui', 'pas', 'sur', 'plus', 'avec', 'être',
  'réunion', 'facture', 'logement', 'voyage', 'recette', 'déménagement',
  'université', 'boulangerie', 'randonnée', 'théâtre',
];
const _es = [
  'el', 'la', 'de', 'que', 'y', 'en', 'un', 'los', 'se', 'del', 'las', //
  'por', 'con', 'una', 'para', 'como', 'más', 'pero', 'reunión', 'factura',
  'vivienda', 'viaje', 'receta', 'mañana', 'niño', 'año', 'biblioteca',
  'presupuesto', 'cumpleaños',
];
const _code = [
  'fn', 'let', 'mut', 'impl', 'struct', 'async', 'await', 'return', //
  'match', 'Some', 'None', 'Ok', 'Err', 'const', 'def', 'self', 'import',
  'class', 'function', 'export', 'type', 'Vec', 'HashMap', 'Result',
];
const _syllables = [
  'ka', 'lo', 'mi', 'ter', 'van', 'son', 'rel', 'dor', 'pa', 'ni', 'que', //
  'stra', 'bel', 'gon', 'fi', 'mo', 'tra', 'lin', 've', 'zu', 'ch', 'ar',
  'en', 'ost', 'um', 'ix', 'or', 'ly', 'sch', 'ber', 'gen', 'hu', 'ri',
  'do', 'ne', 'tal', 'wey', 'pre', 'con',
];

class _Corpus {
  _Corpus() {
    final rng = _Rng(0x5eed);
    tail = [
      for (var i = 0; i < 40000; i++)
        [for (var p = rng.range(2, 4); p > 0; p--) rng.pick(_syllables)]
            .join(),
    ];
  }

  late final List<String> tail;

  String word(_Rng rng, List<String> lang) => rng.below(100) < 85
      ? lang[rng.zipf(lang.length)]
      : tail[rng.zipf(tail.length)];

  String sentence(_Rng rng, List<String> lang) {
    final words = [
      for (var n = rng.range(6, 22); n > 0; n--) word(rng, lang),
      if (rng.below(8) == 0) '${rng.range(1, 99999)}',
    ];
    final s = words.join(' ');
    return '${s[0].toUpperCase()}${s.substring(1)}${rng.pick(const ['.', '.', '.', '?', '!'])}';
  }

  String code(_Rng rng) {
    final out = StringBuffer('```rust\n');
    for (var n = rng.range(4, 18); n > 0; n--) {
      out.write('${'    ' * rng.below(3)}${rng.pick(_code)} '
          '${word(rng, _en)}_${word(rng, _en)} = '
          '${rng.pick(_code)}(${rng.range(0, 4096)});\n');
    }
    out.write('```\n');
    return out.toString();
  }

  String message(_Rng rng, int len) {
    final lang = switch (rng.below(10)) {
      < 5 => _en,
      < 7 => _nl,
      7 => _de,
      8 => _fr,
      _ => _es,
    };
    final out = StringBuffer();
    while (out.length < len) {
      switch (rng.below(10)) {
        case 0:
          out.write('## ${sentence(rng, lang)}\n\n');
        case 1:
          for (var n = rng.range(2, 5); n > 0; n--) {
            out.write('- ${sentence(rng, lang)}\n');
          }
          out.write('\n');
        case 2 when identical(lang, _en):
          out.write(code(rng));
        default:
          for (var n = rng.range(2, 5); n > 0; n--) {
            out.write('${sentence(rng, lang)} ');
          }
          out.write('\n\n');
      }
    }
    final s = out.toString();
    return s.length > len ? s.substring(0, len) : s;
  }

  String title(_Rng rng) {
    final lang = switch (rng.below(4)) { < 2 => _en, 2 => _nl, _ => _de };
    final words = [
      for (var n = rng.range(2, 5); n > 0; n--) word(rng, lang),
      lang[rng.range(lang.length ~/ 2, lang.length - 1)],
    ];
    final t = words.join(' ');
    return '${t[0].toUpperCase()}${t.substring(1)}';
  }
}
