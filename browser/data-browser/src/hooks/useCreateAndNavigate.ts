import { Core, JSONValue, Resource, useStore } from '@tomic/react';
import { useCallback } from 'react';
import toast from 'react-hot-toast';
import { useNavigate } from 'react-router-dom';
import { constructOpenURL } from '../helpers/navigation';

export type CreateAndNavigate = (
  isA: string,
  propVals: Record<string, JSONValue>,
  parent?: string,
  /** Query parameters for the resource / endpoint */
  extraParams?: Record<string, string>,
  onCreated?: (resource: Resource) => Promise<void>,
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
      parent,
      extraParams,
      onCreated,
    ): Promise<Resource> => {
      const classResource = await store.getResource<Core.Class>(isA);

      const resource = await store.newResource({
        isA,
        parent,
        propVals,
      });

      try {
        await resource.save();

        if (onCreated) {
          await onCreated(resource);
        }

        navigate(constructOpenURL(resource.subject, extraParams));
        toast.success(`${classResource.title} created`);
        store.notifyResourceManuallyCreated(resource);
      } catch (e) {
        store.notifyError(e);
      }

      return resource;
    },
    [store, navigate, parent],
  );

  return createAndNavigate;
}
