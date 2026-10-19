import 'dart:convert';

import 'package:atomic_chat/atomic_chat.dart';
import 'package:flutter/foundation.dart';

/// A pretend AI for trying the chat without an account: debug builds only,
/// and only when built with `--dart-define=FAKE_AI=1`. Never in a release
/// build ([kDebugMode] is a constant there, so this is compiled out).
const bool fakeAiEnabled =
    kDebugMode && (_fakeAi == '1' || _fakeAi == 'true');
const _fakeAi = String.fromEnvironment('FAKE_AI');

/// The pretend AI: it searches the drives with the real tool (the first
/// question of each message), then answers in canned Markdown with a bit of
/// everything (headings, lists, code, a table, a quote, a link to the first
/// hit), streamed in small pieces.
HostedAi fakeHostedAi() => HostedAi(
      status: {
        'enabled': true,
        'consent': true,
        'model': 'fake',
        'remaining_micros': 1000000,
      },
      acceptsImages: true,
      completions: _fakeCompletions,
      enable: () async => {'enabled': true, 'consent': true, 'model': 'fake'},
    );

Map<String, dynamic> _delta(Map<String, dynamic> delta) => {
      'choices': [
        {'delta': delta}
      ]
    };

Stream<Map<String, dynamic>> _fakeCompletions(
  List<Map<String, dynamic>> messages,
  String model,
  List<Map<String, dynamic>>? tools,
) async* {
  await Future<void>.delayed(const Duration(milliseconds: 400));
  final last = messages.last;
  final canSearch =
      tools?.any((t) => t['function']?['name'] == 'semantic_search') ?? false;
  if (last['role'] == 'user' && canSearch) {
    final asked = _text(last['content']);
    final query = asked.split(RegExp(r'\s+')).take(3).join(' ');
    yield _delta({'content': 'Let me look in your drives. '});
    await Future<void>.delayed(const Duration(milliseconds: 300));
    yield _delta({
      'tool_calls': [
        {
          'index': 0,
          'id': 'fake_${DateTime.now().millisecondsSinceEpoch}',
          'type': 'function',
          'function': {
            'name': 'semantic_search',
            'arguments': jsonEncode({
              'query': query.isEmpty ? 'notes' : query,
              'description': 'Searching your drives for “'
                  '${query.isEmpty ? 'notes' : query}”',
            }),
          },
        }
      ]
    });
    return;
  }
  var link = '';
  if (last['role'] == 'tool') {
    try {
      final hits = jsonDecode(last['content'] as String);
      if (hits is List && hits.isNotEmpty) {
        link = 'The best match is [${hits.first['title']}]'
            '(${hits.first['subject']}).\n\n';
      } else {
        link = 'I found nothing in your drives for that.\n\n';
      }
    } catch (_) {}
  }
  final answer = '$link$_canned';
  for (var i = 0; i < answer.length; i += 6) {
    await Future<void>.delayed(const Duration(milliseconds: 16));
    yield _delta({
      'content':
          answer.substring(i, i + 6 > answer.length ? answer.length : i + 6),
    });
  }
}

String _text(Object? content) => content is String
    ? content
    : content is List
        ? [
            for (final p in content)
              if (p is Map && p['type'] == 'text') p['text'],
          ].join(' ')
        : '';

const _canned = '''## A plan in three steps

This is **bold**, this is *italic*, this is `inline code` and ~~struck~~.

1. Gather the **notes**
2. Write a draft
   - outline first
   - then the details
     1. nested and numbered
3. Share it: see https://atomic.place

> A quote, which can run long enough to wrap onto a second line on a phone.

```dart
void main() {
  final greeting = 'Hello from a code block with a rather long line that scrolls sideways';
  print(greeting);
}
```

| Step | Owner | Done |
|:--|:--|--:|
| Notes | Joep | 80% |
| Draft | Polle | 10% |

---

That's all.''';
