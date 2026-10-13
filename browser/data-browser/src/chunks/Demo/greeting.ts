// @wc-ignore-file
// (Wuchale: scripted demo dialogue, not app chrome.)

/** The name a guest is given until they pick their own (demoWorkspace.ts). */
const PLACEHOLDER_NAME = 'Demo User';

/**
 * Mara's answer when the visitor says hi in the meeting. Addresses them by
 * first name when the agent has a real one, and plainly when it only has the
 * guest placeholder, so a throwaway "Demo User" is never read back at them.
 */
export function greetingFor(name: string | undefined): string {
  const first = name?.trim().split(/\s+/)[0];
  const known = !!first && name?.trim() !== PLACEHOLDER_NAME;

  return known
    ? `Hi ${first}! 👋 Welcome to the team`
    : 'Hi there! 👋 Welcome to the team';
}
