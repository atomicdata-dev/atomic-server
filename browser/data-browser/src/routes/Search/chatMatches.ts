// @wc-ignore-file
export type ChatMatchKind = 'dm' | 'ai';

export interface ChatCandidate {
  subject: string;
  kind: ChatMatchKind;
  /** Member names (DM) or the chat title (AI chat). */
  names: string[];
  /** Message text that is already loaded locally. Never fetched for search. */
  texts?: string[];
}

export interface ChatMatch {
  subject: string;
  kind: ChatMatchKind;
  /** What matched: a name or title, or the text of a message. */
  via: 'name' | 'message';
}

/** Case-insensitive substring match; an empty query matches nothing. */
export function includesQuery(text: string, query: string): boolean {
  const needle = query.trim().toLowerCase();

  return needle !== '' && text.toLowerCase().includes(needle);
}

/** The readable text of an AI chat log entry: `t`, or the text parts of
 *  `parts` (a JSON string). Reasoning, tool calls and files are skipped. */
export function entryText(entry: { t?: unknown; parts?: unknown }): string {
  if (typeof entry.t === 'string' && entry.t) return entry.t;
  if (typeof entry.parts !== 'string') return '';

  try {
    const parts: unknown = JSON.parse(entry.parts);

    if (!Array.isArray(parts)) return '';

    return parts
      .filter(
        (part): part is { type: 'text'; text: string } =>
          part?.type === 'text' && typeof part.text === 'string',
      )
      .map(part => part.text)
      .join('\n');
  } catch {
    return '';
  }
}

/**
 * The chats a search query finds, name and title matches first, then chats
 * found by a message. Each chat appears once, in the order given.
 */
export function findChatMatches(
  query: string,
  candidates: ChatCandidate[],
): ChatMatch[] {
  if (query.trim() === '') return [];

  const byName: ChatMatch[] = [];
  const byMessage: ChatMatch[] = [];

  for (const { subject, kind, names, texts = [] } of candidates) {
    if (names.some(name => includesQuery(name, query))) {
      byName.push({ subject, kind, via: 'name' });
    } else if (texts.some(text => includesQuery(text, query))) {
      byMessage.push({ subject, kind, via: 'message' });
    }
  }

  return [...byName, ...byMessage];
}
