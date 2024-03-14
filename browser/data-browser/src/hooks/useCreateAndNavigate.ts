import { Core, JSONValue, Resource, useStore } from '@tomic/react';
import { useCallback } from 'react';
import toast from 'react-hot-toast';
import { useNavigate } from 'react-router-dom';
import { constructOpenURL } from '../helpers/navigation';
import { getNamePartFromProps } from '../helpers/getNamePartFromProps';

export type CreateAndNavigate = (
  isA: string,
  propVals: Record<string, JSONValue>,
  parent?: string,
  extraParams?: Record<string, string>,
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

  return useCallback(
    async (
      isA: string,
      propVals: Record<string, JSONValue>,
      parent?: string,
      /** Query parameters for the resource / endpoint */
      extraParams?: Record<string, string>,
    ): Promise<Resource> => {
      const classResource = await store.getResource<Core.Class>(isA);

      const namePart = getNamePartFromProps(propVals);
      const newSubject = await store.buildUniqueSubjectFromParts(
        [classResource.props.shortname, namePart],
        parent,
      );

      const resource = await store.newResource({
        subject: newSubject,
        isA,
        parent,
        propVals,
      });

      try {
        await resource.save();
        navigate(constructOpenURL(newSubject, extraParams));
        toast.success(`${classResource.title} created`);
        store.notifyResourceManuallyCreated(resource);
      } catch (e) {
        store.notifyError(e);
      }

      return resource;
    },
    [store, navigate, parent],
  );
}
