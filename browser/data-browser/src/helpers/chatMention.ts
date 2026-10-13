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

/** Replaces the trigger token with the mention (plus a trailing space).
 * Returns the new text and where the caret goes. */
export const insertMention = (
  text: string,
  trigger: MentionTrigger,
  id: string,
  label: string,
): { text: string; caret: number } => {
  const mention = `${formatMention(id, label)} `;
  const next = text.slice(0, trigger.start) + mention + text.slice(trigger.end);

  return { text: next, caret: trigger.start + mention.length };
};
