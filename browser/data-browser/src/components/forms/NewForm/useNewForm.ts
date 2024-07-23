import {
  Resource,
  useString,
  useStore,
  useResource,
  useArray,
  Core,
  core,
} from '@tomic/react';
import { useState, useEffect } from 'react';

const resourseOpts = { newResource: true };

type UseNewForm = {
  klass: Resource<Core.Class>;
  setSubject: (v: string) => void;
  initialSubject?: string;
  parent?: string;
};

/** Shared logic for NewForm components. */
export const useNewForm = (args: UseNewForm) => {
  const { klass, setSubject, initialSubject, parent } = args;

  const store = useStore();
  const [initialized, setInitialized] = useState(false);

  const [subjectValue, setSubjectValueInternal] = useState<string>(() => {
    if (initialSubject === undefined) {
      return store.createSubject();
    }

    return initialSubject;
  });

  const [subjectErr, setSubjectErr] = useState<Error | undefined>(undefined);
  const resource = useResource(subjectValue, resourseOpts);
  const [parentVal] = useString(resource, core.properties.parent);
  const [isAVal] = useArray(resource, core.properties.isA);

  // When the resource is created or updated, make sure that the parent and class are present
  useEffect(() => {
    (async () => {
      if (!resource.new) {
        // The resource we are trying to create already exists, don't update any values.
        return;
      }

      if (parentVal !== parent) {
        await resource.set(core.properties.parent, parent);
      }

      if (isAVal.length === 0) {
        await resource.addClasses(klass.subject);
      }

      setInitialized(true);
    })();
  }, [resource]);

  async function setSubjectValue(newSubject: string) {
    setSubjectValueInternal(newSubject);
    setSubjectErr(undefined);
    setSubject(newSubject);

    if (resource.get(core.properties.parent) !== parent) {
      // This prevents that we move an empty temporary resource
      return;
    }

    try {
      await store.renameSubject(resource, newSubject);
    } catch (e) {
      setSubjectErr(e);
    }
  }

  return {
    subjectErr,
    subjectValue,
    setSubjectValue,
    resource,
    initialized,
  };
};
