import type { AtomicValue } from '@tomic/react';

/** Values like JSON objects can't be React children, so they're written out as text. */
export function formatPlainValue(val: AtomicValue): string {
  if (val === null || val === undefined) {
    return '';
  }

  if (typeof val === 'object') {
    try {
      return JSON.stringify(val);
    } catch {
      return '';
    }
  }

  return String(val);
}

/**
 * The value as a subject to look up, or `undefined` when it is not a string.
 * A stored value can be an object or a number where a column expects a link;
 * `useResource` needs a string, and throws on anything else.
 */
export function asSubject(val: unknown): string | undefined {
  return typeof val === 'string' && val !== '' ? val : undefined;
}
