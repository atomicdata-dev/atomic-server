// @wc-ignore-file
import { canonicalizeScheme } from '@tomic/lib';

export interface ActivityRow {
  subject: string;
  /** Time of the newest activity, ms. */
  at?: number;
  /** What that activity was. */
  kind?: 'edited' | 'commented';
}

/**
 * The newest comment time per commented resource. A thread is a ChatLog page
 * (newest entry time) or an old Message resource (its creation time); several
 * threads about one resource keep the newest. Threads without `about` or a
 * time say nothing.
 */
export function newestCommentTimes(
  threads: { about?: string; at?: number }[],
): Map<string, number> {
  const out = new Map<string, number>();

  for (const { about, at } of threads) {
    const key = about && canonicalizeScheme(about);

    if (key && at && at > (out.get(key) ?? 0)) {
      out.set(key, at);
    }
  }

  return out;
}

/**
 * Edits and comments as one list, newest first. A resource counts at its
 * newest activity: a comment newer than its last edit shows as "commented",
 * anything else as "edited". Resources with an unknown time sort last and
 * carry no kind.
 */
export function mergeActivity(
  edits: { subject: string; at?: number }[],
  comments: ReadonlyMap<string, number>,
): ActivityRow[] {
  const rows = edits.map(({ subject, at }): ActivityRow => {
    const commentedAt = comments.get(canonicalizeScheme(subject));

    if (commentedAt !== undefined && commentedAt > (at ?? 0)) {
      return { subject, at: commentedAt, kind: 'commented' };
    }

    return { subject, at, kind: at ? 'edited' : undefined };
  });

  return rows.sort((a, b) => (b.at ?? 0) - (a.at ?? 0));
}
