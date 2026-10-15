import { canonicalIdentifier, core, type Resource } from '@tomic/react';

/**
 * Who is in a conversation, as a sorted list of canonical identities. The same
 * agent can be spelled `did:ad:agent:X` or `atomic:agent:X`, so members are
 * never compared as raw strings.
 */
export function canonicalMembers(members: string[]): string[] {
  return [...new Set(members.map(canonicalIdentifier))].sort();
}

/** The members of a loaded conversation, or undefined while it has none. */
export function membersOf(conversation: Resource): string[] | undefined {
  const read = conversation.get(core.properties.read);

  return Array.isArray(read) ? canonicalMembers(read as string[]) : undefined;
}

/** Whether `a` and `b` hold the same people, whatever their spelling. */
export function sameMembers(a: string[], b: string[]): boolean {
  const left = canonicalMembers(a);
  const right = canonicalMembers(b);

  return (
    left.length === right.length &&
    left.every((member, index) => member === right[index])
  );
}

export interface DedupedConversations {
  /** One subject per member set, in the order given. */
  subjects: string[];
  /** Per kept subject, the subjects that were collapsed into it. */
  twins: Map<string, string[]>;
}

/**
 * Collapses conversations that have the same members into one entry, keeping
 * the first one listed (the private drive's list comes first, so that is the
 * one this person opened before). A conversation that is not loaded yet is
 * kept as it is: it cannot be compared until it is.
 */
export function dedupeByMembers(
  subjects: string[],
  resources: Map<string, Resource>,
): DedupedConversations {
  const keptByMembers = new Map<string, string>();
  const kept: string[] = [];
  const twins = new Map<string, string[]>();

  for (const subject of subjects) {
    const resource = resources.get(subject);
    const members =
      resource && !resource.loading ? membersOf(resource) : undefined;

    if (!members || members.length === 0) {
      kept.push(subject);
      continue;
    }

    const key = members.join('\n');
    const first = keptByMembers.get(key);

    if (first === undefined) {
      keptByMembers.set(key, subject);
      kept.push(subject);
    } else {
      twins.set(first, [...(twins.get(first) ?? []), subject]);
    }
  }

  return { subjects: kept, twins };
}
