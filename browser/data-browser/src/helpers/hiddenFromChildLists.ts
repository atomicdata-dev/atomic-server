import { ai, dataBrowser } from '@tomic/lib';

/** Classes kept out of child lists (the AI sidebar and meeting UI reach them). */
export const HIDDEN_CLASSES: string[] = [
  ai.classes.aiChat,
  dataBrowser.classes.meeting,
];

/**
 * Is a resource hidden from child lists? True for the classes above and for
 * anything with an `about` value: annotations of another resource (private
 * agent notes, AI chats). Not decided by PlainText, users make those too.
 */
export function isHiddenFromChildLists(
  classes: readonly string[],
  about?: string | null,
): boolean {
  return !!about || classes.some(c => HIDDEN_CLASSES.includes(c));
}
