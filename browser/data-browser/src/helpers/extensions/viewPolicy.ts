// @wc-ignore-file
import { core, urls, type Resource, type Store } from '@tomic/react';

/** Host-selected profiles, never accepted from iframe request arguments. */
export type ViewPolicy =
  | { kind: 'app'; root: string }
  | { kind: 'packaged'; root: string; classes: string[]; agent?: string };

/** Shared scope decision. Actual writes retain their existing signing identity. */
export async function canViewAccess(
  store: Pick<Store, 'getResource'>,
  subject: string,
  policy: ViewPolicy,
  access: 'read' | 'write',
): Promise<boolean> {
  // Generated views retain the signed-in user's read scope. Fetch failures are
  // still errors; this is not authorization to bypass Store/server reads.
  if (policy.kind === 'app' && access === 'read') {
    const resource = await store.getResource(subject);
    if (resource.error) throw resource.error;

    return true;
  }

  const roots = [
    policy.root,
    ...(policy.kind === 'packaged' && access === 'read' ? policy.classes : []),
  ];
  const seen = new Set<string>();
  let current: string | undefined = subject;

  for (
    let depth = 0;
    current && (policy.kind === 'packaged' || depth < 12);
    depth++
  ) {
    if (seen.has(current)) return false;
    seen.add(current);
    if (roots.includes(current)) return true;
    const resource: Resource = await store.getResource(current);
    if (resource.error) throw resource.error;

    if (policy.kind === 'packaged') {
      const writes = resource.get(core.properties.write);
      if (
        policy.agent &&
        Array.isArray(writes) &&
        writes.includes(policy.agent)
      )
        return true;

      if (access === 'read') {
        const reads = resource.get(core.properties.read);
        if (
          Array.isArray(reads) &&
          reads.some(
            agent =>
              agent === urls.instances.publicAgent ||
              (policy.agent && agent === policy.agent),
          )
        )
          return true;
      }
    }

    const parent = resource.get(core.properties.parent);
    current = typeof parent === 'string' ? parent : undefined;
  }

  return false;
}
