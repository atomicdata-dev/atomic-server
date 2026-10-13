import { isCalendarDate } from '@tomic/lib';

/**
 * The date to commit for a "Last day" draft, or undefined when the draft is
 * empty, an incomplete intermediate value or equal to what is already saved.
 */
export function untilDateToCommit(
  draft: string | null,
  current: string,
): string | undefined {
  if (draft === null || draft === current) return undefined;

  return isCalendarDate(draft) ? draft : undefined;
}
