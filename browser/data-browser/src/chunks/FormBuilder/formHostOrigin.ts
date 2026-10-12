import { useStore } from '@tomic/react';
import { useEffect, useState } from 'react';
import { getManagedEnrollments } from '@helpers/managed/enrollmentApi';
import type { ManagedEnrollmentSummary } from '@helpers/managed/enrollmentApi';
import { getManagedPortalUrl } from '@helpers/managed/cloudSync';
import { isOriginWithoutNode } from '@helpers/originNode';

function httpOrigin(url: string | null | undefined): string | undefined {
  if (!url) return undefined;

  try {
    const parsed = new URL(url);

    return ['http:', 'https:'].includes(parsed.protocol)
      ? parsed.origin
      : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The origin of the node that hosts `drive`, which is where a guest has to go
 * to open a form. A Cloud Server enrollment names it (`http_origin`) and wins,
 * because the store's server URL can be the shared static origin of the hosted
 * app, which is no node and answers a form link with a 404. Otherwise the
 * store's server URL counts unless it is known to run no node. `undefined`
 * means nothing hosts this drive.
 */
export function resolveFormHostOrigin(
  drive: string | undefined,
  serverUrl: string | undefined,
  enrollments: ManagedEnrollmentSummary[],
): string | undefined {
  const hosted = enrollments.find(
    e =>
      e.drive_subject === drive &&
      // Same rule as reconcile.ts: a placement without data, or a suspended
      // one, is not a node that serves the drive.
      (e.status === /* @wc-ignore */ 'Active' ||
        e.status === /* @wc-ignore */ 'Error') &&
      e.resource_count !== 0,
  );
  const hostedOrigin = httpOrigin(hosted?.http_origin);

  if (hostedOrigin) return hostedOrigin;

  const origin = httpOrigin(serverUrl);

  return origin && !isOriginWithoutNode(origin) ? origin : undefined;
}

/**
 * `{ origin, pending }`: the hosting node's origin for the current drive.
 * `pending` while enrollments are still loading and nothing else answers yet,
 * so the nudge does not flash for someone whose drive is hosted.
 */
export function useFormHostOrigin(): {
  origin: string | undefined;
  pending: boolean;
} {
  const store = useStore();
  const drive = store.getDrive();
  const serverUrl = store.getServerUrl();
  const hasPortal = getManagedPortalUrl() !== null;
  const [enrollments, setEnrollments] = useState<
    ManagedEnrollmentSummary[] | undefined
  >();

  useEffect(() => {
    if (!hasPortal) return;

    let cancelled = false;

    getManagedEnrollments()
      .catch(() => [] as ManagedEnrollmentSummary[])
      .then(list => {
        if (!cancelled) setEnrollments(list);
      });

    return () => {
      cancelled = true;
    };
  }, [hasPortal, drive]);

  const origin = resolveFormHostOrigin(drive, serverUrl, enrollments ?? []);

  return { origin, pending: hasPortal && !origin && enrollments === undefined };
}
