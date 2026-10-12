import {
  Resource,
  Store,
  useString,
  useStore,
  useResource,
  useArray,
  Core,
  core,
  isAtomicIdentifier,
  GENESIS,
  type JSONValue,
} from '@tomic/react';
import { useState, useEffect } from 'react';

const resourseOpts = { newResource: true };

type UseNewFormOptions = {
  klass: Resource<Core.Class>;
  setSubject: (v: string) => void;
  initialSubject?: string;
  parent?: string;
  /** Values the draft starts with. Only used when a new draft is created. */
  initialProps?: Record<string, JSONValue>;
};

/**
 * Whether the subject from the URL is a draft this form can keep editing.
 *
 * An HTTP subject is one the user typed, and is kept. A DID is only usable
 * while this session still holds the draft it was minted for: its genesis
 * certificate lives on that draft, so after a reload the DID has nothing
 * behind it and the form starts a fresh draft instead.
 */
function canReuse(store: Store, subject: string | undefined): boolean {
  if (subject === undefined) return false;
  if (!isAtomicIdentifier(subject)) return true;

  return (
    store.getResourceLoading(subject, resourseOpts).get(GENESIS) !== undefined
  );
}

/** Shared logic for NewForm components. */
export const useNewForm = ({
  klass,
  setSubject,
  initialSubject,
  parent,
  initialProps,
}: UseNewFormOptions) => {
  const store = useStore();
  const [initialized, setInitialized] = useState(false);

  // The draft gets its final subject up front from `store.newResource`, which
  // is async, so the form has no subject for the first render or two.
  const [subjectValue, setSubjectValueInternal] = useState<string | undefined>(
    () => (canReuse(store, initialSubject) ? initialSubject : undefined),
  );

  const [subjectErr, setSubjectErr] = useState<Error | undefined>(undefined);
  const resource = useResource(subjectValue, resourseOpts);
  const [parentVal] = useString(resource, core.properties.parent);
  const [isAVal] = useArray(resource, core.properties.isA);

  useEffect(() => {
    if (subjectValue !== undefined) return;

    let cancelled = false;

    // NOTE: a Property created through this generic form keeps an ordinary
    // genesis subject (legacy). A content-addressed ID needs parent, shortname
    // and datatype before the subject exists, which this form only learns
    // while the user fills it in. Table columns, ontology properties and the
    // form builder create content-addressed Properties instead.
    //
    // The genesis is signed on the first save, so it carries everything the
    // user fills in, and a form that is never saved sends nothing.
    store
      .newResource({
        parent,
        noParent: !parent,
        isA: klass.subject,
        propVals: initialProps,
        deferGenesis: true,
      })
      .then(draft => {
        if (cancelled) return;

        setSubjectValueInternal(draft.subject);
        setSubject(draft.subject);
      })
      .catch(e => {
        if (!cancelled) setSubjectErr(e);
      });

    return () => {
      cancelled = true;
    };
    // Mint once per missing draft; the other inputs only seed it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [subjectValue, store]);

  // When the resource is created or updated, make sure that the parent and class are present
  useEffect(() => {
    if (subjectValue === undefined) return;

    (async () => {
      if (!resource.new) {
        // The resource we are trying to create already exists, don't update any values.
        return;
      }

      if (parent && !parentVal) {
        await resource.set(core.properties.parent, parent);
      }

      if (isAVal.length === 0) {
        await resource.addClasses(klass.subject);
      }

      setInitialized(true);
    })();
  }, [subjectValue, resource, parentVal, parent, isAVal.length, klass.subject]);

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
    subjectValue: subjectValue ?? '',
    setSubjectValue,
    resource,
    initialized,
  };
};
