import { core, type Store } from '@tomic/react';
import { isContentAddressed } from './propertyIdentity';

/**
 * Why `subject` cannot be re-parented under `target`, or undefined when it can.
 * Walks the loaded `parent` chain of the target: a cycle ends the walk.
 */
export function moveBlockedReason(
  store: Pick<Store, 'getResourceLoading' | 'driveOfSubject'>,
  subject: string,
  target: string,
): string | undefined {
  if (isContentAddressed(subject)) {
    return "A property can't be moved to another parent.";
  }

  const seen = new Set<string>();

  for (let at: string | undefined = target; at && !seen.has(at); ) {
    if (at === subject) {
      return at === target
        ? "A resource can't be moved into itself."
        : "A resource can't be moved into something inside it.";
    }

    seen.add(at);
    at = store.getResourceLoading(at).get(core.properties.parent) as
      | string
      | undefined;
  }

  if (store.driveOfSubject(subject) !== store.driveOfSubject(target)) {
    return 'Moving to another drive is not supported yet.';
  }

  return undefined;
}
