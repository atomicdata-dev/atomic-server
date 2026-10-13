import { JSONValue, Resource, useStore } from '@tomic/react';
import { useCallback } from 'react';
import toast from 'react-hot-toast';
import { constructOpenURL } from '../helpers/navigation';
import { useNavigate } from '@tanstack/react-router';

export type CreateAndNavigate = (
  isA: string,
  propVals: Record<string, JSONValue>,
  options: {
    parent?: string;
    noParent?: boolean;
    extraParams?: Record<string, string>;
    /** Query parameters for the resource / endpoint */
    onCreated?: (resource: Resource) => Promise<void> | void;
    /** Only pass subject if you really need a custom subject. Random ULID are prefered in most cases. */
    subject?: string;
    /** If true, skip navigation after resource creation */
    skipNavigation?: boolean;
    /** If true, skip notifying the store after resource creation */
    skipNotify?: boolean;
  },
) => Promise<Resource>;

/**
 * Hook that builds a function that will create a new resource with the given
 * properties and then navigate to it.
 *
 * @returns A {@link CreateAndNavigate} function.
 */
export function useCreateAndNavigate(): CreateAndNavigate {
  const store = useStore();
  const navigate = useNavigate();

  const createAndNavigate: CreateAndNavigate = useCallback(
    async (
      isA,
      propVals,
      { parent, extraParams, onCreated, subject, noParent, skipNavigation },
    ): Promise<Resource> => {
      const resource = await store.newResource({
        subject,
        isA,
        parent,
        propVals,
        noParent,
      });

      try {
        await resource.save();

        if (onCreated) {
          await onCreated(resource);
        }

        // Notify subscribers (collections, sidebars, message lists) BEFORE
        // navigation so the optimistic-add path runs synchronously
        // against the still-active DOM. If we navigate first, the route
        // change can suspend or re-render before
        // `applyResourceChange` has a chance to settle into the
        // collection, and downstream `expect(...).toBeVisible()` checks
        // poll the new page mid-mount instead of seeing the new
        // resource immediately.
        store.notifyResourceManuallyCreated(resource);

        if (!skipNavigation) {
          await navigate({
            to: constructOpenURL(resource.subject, extraParams),
          });
        }
      } catch (e) {
        store.notifyError(e);
        toast.error('Failed to save new resource');
      }

      return resource;
    },
    [store, navigate],
  );

  return createAndNavigate;
}
