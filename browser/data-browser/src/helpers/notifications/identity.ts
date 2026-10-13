// @wc-ignore-file
import { canonicalIdentifier } from '@tomic/lib';

/** A notification's logical identity is its source event, within one private drive.
 * ChatLog fragments identify individual messages and must survive normalization. */
export function notificationSourceId(source: string): string {
  const fragment = source.indexOf('#');

  return fragment < 0
    ? canonicalIdentifier(source)
    : canonicalIdentifier(source.slice(0, fragment)) + source.slice(fragment);
}
