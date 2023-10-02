import {
  JSONValue,
  properties,
  Resource,
  useResource,
  useStore,
  useTitle,
} from '@tomic/react';
import { useCallback } from 'react';
import toast from 'react-hot-toast';
import { useNavigate } from 'react-router-dom';
import { constructOpenURL } from '../../helpers/navigation';
import { getNamePartFromProps } from '../../helpers/getNamePartFromProps';

/**
 * Hook that builds a function that will create a new resource with the given
 * properties and then navigate to it.
 *
 * @param klass The type of resource to create a new instance of.
 * @param parent The parent resource of the new resource.
 * @returns A createAndNavigate function.
 */
export function useCreateAndNavigate(klass: string, parent?: string) {
  const store = useStore();
  const classTypeResource = useResource(klass);
  const [title] = useTitle(classTypeResource);
  const navigate = useNavigate();

  return useCallback(
    async (
      className: string,
      propVals: Record<string, JSONValue>,
      /** Query parameters for the resource / endpoint */
      extraParams?: Record<string, string>,
      /** Do not set a parent for the new resource. Useful for top-level resources */
      noParent?: boolean,
    ): Promise<Resource> => {
      const namePart = getNamePartFromProps(propVals);
      const newSubject = await store.buildUniqueSubjectFromParts(
        [className, namePart],
        noParent ? undefined : parent,
      );

      const resource = new Resource(newSubject, true);

      await Promise.all([
        ...Object.entries(propVals).map(([key, val]) =>
          resource.set(key, val, store),
        ),
        !noParent && resource.set(properties.parent, parent, store),
      ]);

      try {
        await resource.save(store);
        navigate(constructOpenURL(newSubject, extraParams));
        toast.success(`${title} created`);
        store.notifyResourceManuallyCreated(resource);
      } catch (e) {
        store.notifyError(e);
      }

      return resource;
    },
    [store, classTypeResource, title, navigate, parent],
  );
}
