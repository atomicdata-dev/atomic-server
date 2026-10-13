import { useEffect, useState } from 'react';
import { server, useStore, type Resource } from '@tomic/react';
import { managedFetch } from '../../helpers/managed/api';
import { getManagedPortalUrl } from '../../helpers/managed/cloudSync';

export interface EditorSeats {
  drive: string;
  used?: number;
  included?: number;
}

/**
 * Hosted Atomic bills per editor, so inviting someone to edit uses a seat.
 * Undefined unless the drive this resource lives in has a seat-based plan
 * (and while that is being looked up).
 */
export function useEditorSeats(target: Resource): EditorSeats | undefined {
  const store = useStore();
  const isSaas = !!getManagedPortalUrl();
  const [seats, setSeats] = useState<EditorSeats>();
  const drive = target.hasClasses(server.classes.drive)
    ? target.subject
    : store.getDrive();

  useEffect(() => {
    setSeats(undefined);
    if (!isSaas || !drive) return;
    const controller = new AbortController();
    void managedFetch(
      `/billing/subscription?${new URLSearchParams({ drive })}`,
      { signal: controller.signal },
    )
      .then(async response => {
        if (!response.ok || response.status === 204) return;
        const subscription = await response.json();
        if (
          controller.signal.aborted ||
          subscription.plan !== 'server' ||
          subscription.status === 'canceled'
        )
          return;
        setSeats({
          drive,
          used: subscription.editors_used,
          included: subscription.editors_included,
        });
      })
      .catch(() => {
        /* Do not imply hosting when billing is unavailable. */
      });

    return () => controller.abort();
  }, [isSaas, drive]);

  return seats?.drive === drive ? seats : undefined;
}

/** "3 of 5 editor seats available on this drive. Viewers are free." */
export function describeEditorSeats(seats: EditorSeats): string {
  const text =
    Number.isSafeInteger(seats.used) && Number.isSafeInteger(seats.included)
      ? `${Math.max(0, seats.included! - seats.used!)} of ${seats.included} editor seats available on this drive.`
      : 'Editor seat availability for this drive is unavailable.';

  return `${text} Viewers are free.`;
}
