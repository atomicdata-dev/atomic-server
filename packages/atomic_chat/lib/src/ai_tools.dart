import 'assistant_api.dart';
import 'hosted_ai.dart';
import 'resource_row.dart';

/// Most hits [semanticSearchTool] returns, and how many of them come with a
/// piece of their text.
const _maxHits = 20;
const _hitsWithText = 5;

/// Most resources [getResourceTool] reads in one call, and characters of each.
const _maxRead = 5;
const _readChars = 3000;

/// The tools the assistant gives the model: reading the person's data, never
/// changing it. Named and shaped as the web app's tools of the same name, so
/// a chat reads the same in both.
List<AiTool> assistantTools(AssistantApi api) =>
    [semanticSearchTool(api), getResourceTool(api)];

/// `semantic_search`: searches the drives on this device. Its result, a list
/// of `{subject, title, chunk}`, is what the web app shows for it.
AiTool semanticSearchTool(AssistantApi api) => AiTool(
      name: 'semantic_search',
      description:
          "Search the person's drives on this device for resources. Returns "
          'the subject, title and the start of the text of each hit. Read a '
          'hit in full with get_atomic_resource.',
      parameters: {
        'type': 'object',
        'properties': {
          'query': {
            'type': 'string',
            'description': 'What to search for.',
          },
          'description': {
            'type': 'string',
            'description': 'A short one sentence description of the search '
                'to tell the person what you are doing, e.g. "Searching for '
                'your notes on Lisbon".',
          },
          'limit': {
            'type': 'integer',
            'description': 'The most results to return, 1 - 20.',
          },
        },
        'required': ['query', 'description'],
      },
      execute: (input) async {
        final query = '${input['query'] ?? ''}'.trim();
        if (query.isEmpty) throw StateError('No query given');
        final limit =
            ((input['limit'] as num?)?.toInt() ?? 10).clamp(1, _maxHits);
        final hits = (await api.search(query)).take(limit).toList();
        return [
          for (var i = 0; i < hits.length; i++)
            {
              'subject': hits[i].subject,
              'title': hits[i].title.isEmpty ? 'Untitled' : hits[i].title,
              'chunk': i < _hitsWithText
                  ? await api
                      .resourceText(hits[i].subject, maxChars: 300)
                      .catchError((Object _) => '')
                  : classLabel(hits[i].className),
            },
        ];
      },
    );

/// `get_atomic_resource`: reads resources by their subjects. Its result maps
/// each subject to its readable text.
AiTool getResourceTool(AssistantApi api) => AiTool(
      name: 'get_atomic_resource',
      description: 'Read resources (documents, tables, folders, chats…) by '
          'their subjects: their title, class, properties and text.',
      parameters: {
        'type': 'object',
        'properties': {
          'subjects': {
            'type': 'array',
            'items': {'type': 'string'},
            'description': 'The subjects of the resources to read.',
          },
        },
        'required': ['subjects'],
      },
      execute: (input) async {
        final raw = input['subjects'];
        final subjects = [
          if (raw is List)
            for (final s in raw)
              if (s is String && s.isNotEmpty) s,
          if (raw is String) raw,
        ];
        if (subjects.isEmpty) throw StateError('No subjects given');
        return {
          for (final s in subjects.take(_maxRead))
            s: await api
                .resourceText(s, maxChars: _readChars)
                .catchError((Object e) => 'Error: $e'),
        };
      },
    );
