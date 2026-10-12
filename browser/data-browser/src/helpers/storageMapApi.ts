import { signRequest, type Agent } from '@tomic/react';
import type { ResourceUsage } from './storageMap';

/**
 * Per-resource storage of a drive. Signed like `fetchNodeDriveUsage`; returns
 * null when the node is unreachable, the agent may not read the drive, or the
 * node predates the endpoint.
 */
export async function fetchDriveBreakdown(
  serverUrl: string,
  driveSubject: string,
  agent: Agent,
): Promise<ResourceUsage[] | null> {
  if (!serverUrl || !driveSubject || !agent?.subject) return null;

  const url = new URL('/drive-usage/breakdown', serverUrl);
  url.searchParams.set('subject', driveSubject);

  try {
    const headers = await signRequest(url.toString(), agent, {
      Accept: 'application/json',
    });
    const res = await fetch(url.toString(), { headers });

    if (!res.ok) return null;

    const data = await res.json();

    if (!Array.isArray(data?.resources)) return null;

    return data.resources.map((r: Record<string, unknown>) => ({
      subject: String(r.subject),
      name: typeof r.name === 'string' ? r.name : null,
      parent: typeof r.parent === 'string' ? r.parent : null,
      isA: typeof r.isA === 'string' ? r.isA : null,
      loroBytes: Number(r.loroBytes ?? 0),
      blobBytes: Number(r.blobBytes ?? 0),
    }));
  } catch {
    return null;
  }
}
