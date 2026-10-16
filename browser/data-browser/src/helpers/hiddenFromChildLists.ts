import { ai, dataBrowser, isAgentSubject } from '@tomic/lib';

/** Classes kept out of child lists (the AI sidebar and meeting UI reach them). */
export const HIDDEN_CLASSES: string[] = [
  ai.classes.aiChat,
  dataBrowser.classes.meeting,
];

/**
 * Is a resource hidden from child lists? True for the classes above and for a
 * PlainText about an agent (a private note on that agent, see agentNotes.ts).
 * Any other `about` stays visible: users can set it on their own documents.
 */
export function isHiddenFromChildLists(
  classes: readonly string[],
  about?: string | null,
): boolean {
  if (classes.some(c => HIDDEN_CLASSES.includes(c))) return true;

  return (
    !!about &&
    isAgentSubject(about) &&
    classes.includes(dataBrowser.classes.plainText)
  );
}
