/** The `@query` token the caret is currently in, if any. */
export interface MentionTrigger {
  /** Index of the `@` in the text. */
  start: number;
  /** Index just after the query (the caret). */
  end: number;
  query: string;
}

/**
 * Finds an open `@mention` token ending at `caret`. The `@` must start the
 * text or follow whitespace (so emails don't trigger) and the query may not
 * contain whitespace.
 */
export const findMentionTrigger = (
  text: string,
  caret: number,
): MentionTrigger | undefined => {
  const before = text.slice(0, caret);
  const match = /(^|\s)@([^\s@[\]]*)$/.exec(before);

  if (!match) return undefined;

  const query = match[2];

  return { start: caret - query.length - 1, end: caret, query };
};

/**
 * Serializes a mention in the format chat messages already render
 * (`remarkMention` in MarkdownMention.tsx), same as the AI chat input.
 */
export const formatMention = (id: string, label: string): string => {
  const clean = (v: string) =>
    v.replaceAll('"', '&quot;').replaceAll(/[\][\n\r]+/g, ' ');

  return `[@ id="${clean(id)}" label="${clean(label)}"]`;
};

export interface RecordedMention {
  id: string;
  label: string;
}

/** The label as shown in the composer: one line, no brackets. */
const plainLabel = (label: string) => label.replaceAll(/[\][\n\r]+/g, ' ');

/** Replaces the trigger token with `@Label ` (the stored markup is made by
 * `serializeMentions` on send). Returns the new text and the caret. */
export const insertMention = (
  text: string,
  trigger: MentionTrigger,
  label: string,
): { text: string; caret: number } => {
  const mention = `@${plainLabel(label)} `;
  const next = text.slice(0, trigger.start) + mention + text.slice(trigger.end);

  return { text: next, caret: trigger.start + mention.length };
};

/**
 * Turns the recorded `@Label` mentions in `text` into stored markup. An `@`
 * must start the text or follow whitespace and the label must end at the end,
 * whitespace or punctuation. Each recording is used once; mentions the user
 * edited or deleted stay plain text.
 */
export const serializeMentions = (
  text: string,
  mentions: RecordedMention[],
): string => {
  const queues = new Map<string, RecordedMention[]>();

  for (const m of mentions) {
    const label = plainLabel(m.label);

    if (label) queues.set(label, [...(queues.get(label) ?? []), m]);
  }

  if (queues.size === 0) return text;

  const labels = [...queues.keys()]
    .sort((a, b) => b.length - a.length)
    .map(l => l.replaceAll(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const re = new RegExp(
    `(?<!\\S)@(${labels.join('|')})(?=$|[\\s.,;:!?)])`,
    'g',
  );

  return text.replace(re, (match, label: string) => {
    const m = queues.get(label)?.shift();

    return m ? formatMention(m.id, m.label) : match;
  });
};
