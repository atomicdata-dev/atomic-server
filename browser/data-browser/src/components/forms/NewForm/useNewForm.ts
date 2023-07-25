import {
  Resource,
  useString,
  properties,
  useStore,
  useResource,
  useArray,
} from '@tomic/react';
import { useState, useEffect } from 'react';

const resourseOpts = { newResource: true };

type UseNewForm = {
  klass: Resource;
  setSubject: (v: string) => void;
  initialSubject?: string;
  parent?: string;
};

/** Shared logic for NewForm components. */
export const useNewForm = (args: UseNewForm) => {
  const { klass, setSubject, initialSubject, parent } = args;

  const store = useStore();
  const [klassShortname] = useString(klass, properties.shortname);
  const [subjectValue, setSubjectValueInternal] = useState<string>(() => {
    if (initialSubject === undefined) {
      return store.createSubject(klassShortname);
    }

    return initialSubject;
  });

  const [subjectErr, setSubjectErr] = useState<Error | undefined>(undefined);
  const resource = useResource(subjectValue, resourseOpts);
  const [parentVal, setParent] = useString(resource, properties.parent);
  const [isAVal, setIsA] = useArray(resource, properties.isA);

  // When the resource is created or updated, make sure that the parent and class are present
  useEffect(() => {
    if (parentVal !== parent) {
      setParent(parent);
    }

    if (isAVal.length === 0) {
      setIsA([klass.getSubject()]);
    }
  }, [resource, parent]);

  async function setSubjectValue(newSubject: string) {
    setSubjectValueInternal(newSubject);
    setSubjectErr(undefined);
    setSubject(newSubject);

    if (resource.get(properties.parent) !== parent) {
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
  };
};
