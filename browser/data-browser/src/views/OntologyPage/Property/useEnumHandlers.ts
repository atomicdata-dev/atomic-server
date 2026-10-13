import {
  Resource,
  Core,
  core,
  getEffectiveConstraint,
  setClassConstraint,
  useArray,
  useStore,
  Store,
  DataBrowser,
} from '@tomic/react';
import { useCallback } from 'react';
import { optionSubjects } from '../../../helpers/withConstraint';

export function useEnumHandlers(
  property: Resource<Core.Property>,
  ontology: Resource<Core.Ontology>,
) {
  const store = useStore();

  const [allowsOnly, setAllowsOnly] = useArray(
    property,
    core.properties.allowsOnly,
    { commit: true },
  );
  const [instances, setInstances] = useArray(
    ontology,
    core.properties.instances,
    { commit: true },
  );

  const addTag = useCallback(
    async (tag: Resource) => {
      const newTags = [...allowsOnly, tag.subject];
      const newInstances = [...(instances ?? []), tag.subject];

      await setAllowsOnly(newTags);
      await setInstances(newInstances);

      await tag.save();
    },
    [instances, allowsOnly, setAllowsOnly, setInstances],
  );

  const removeTag = useCallback(
    async (subject: string) => {
      const filteredTags = allowsOnly.filter(tag => tag !== subject);
      await setAllowsOnly(filteredTags);

      // If the tag is not used in any other property, remove from ontology and delete it.
      if (!(await isTagUsed(subject, ontology, store))) {
        const filteredInstances = instances?.filter(
          instance => instance !== subject,
        );

        await setInstances(filteredInstances);
        await store.getResourceLoading(subject).destroy();
      }
    },
    [allowsOnly, setAllowsOnly, instances, setInstances, store],
  );

  return {
    addTag,
    removeTag,
  };
}

const isTagUsed = async (
  tagSubject: string,
  ontology: Resource<Core.Ontology>,
  store: Store,
) => {
  const tag = store.getResourceLoading<DataBrowser.Tag>(tagSubject);

  if (tag.props.parent !== ontology.subject) {
    return true;
  }

  for (const property of ontology.props.properties ?? []) {
    const propertyResource = await store.getResource(property);

    if (propertyResource.props.allowsOnly?.includes(tagSubject)) {
      return true;
    }
  }

  // ...or listed as an option in the constraints of one of its classes.
  for (const classSubject of ontology.props.classes ?? []) {
    const klass = await store.getResource(classSubject);

    for (const propertySubject of [
      ...(klass.get(core.properties.requires) ?? []),
      ...(klass.get(core.properties.recommends) ?? []),
    ] as string[]) {
      if (
        getEffectiveConstraint(
          store,
          [classSubject],
          propertySubject,
        ).enum?.includes(tagSubject)
      ) {
        return true;
      }
    }
  }

  return false;
};

/**
 * Add and remove handlers for the options of a property as one class sees it:
 * the `enum` in the class's `constraints`. Same bookkeeping as
 * {@link useEnumHandlers}: a new tag is registered on the ontology, and a
 * removed one is deleted when nothing else uses it.
 */
export function useClassEnumHandlers(
  classResource: Resource,
  propertySubject: string,
  ontology: Resource<Core.Ontology>,
) {
  const store = useStore();
  const [, setInstances] = useArray(ontology, core.properties.instances, {
    commit: true,
  });

  // Read the list when the handler runs, not from the render that built it:
  // several tags added in a row would otherwise each start from the same
  // stale list and keep only the last one.
  const currentOptions = useCallback(
    () =>
      optionSubjects(
        getEffectiveConstraint(store, [classResource.subject], propertySubject),
      ),
    [store, classResource, propertySubject],
  );
  const currentInstances = useCallback(
    () => (ontology.get(core.properties.instances) ?? []) as string[],
    [ontology],
  );

  const saveOptions = useCallback(
    async (next: string[]) => {
      await setClassConstraint(classResource, propertySubject, {
        enum: next.length > 0 ? next : undefined,
      });
      await classResource.save();
    },
    [classResource, propertySubject],
  );

  const addTag = useCallback(
    async (tag: Resource) => {
      await tag.save();
      await setInstances([...currentInstances(), tag.subject]);
      await saveOptions([...currentOptions(), tag.subject]);
    },
    [currentInstances, currentOptions, setInstances, saveOptions],
  );

  const removeTag = useCallback(
    async (subject: string) => {
      await saveOptions(currentOptions().filter(tag => tag !== subject));

      if (!(await isTagUsed(subject, ontology, store))) {
        await setInstances(
          currentInstances().filter(instance => instance !== subject),
        );
        await store.getResourceLoading(subject).destroy();
      }
    },
    [
      currentOptions,
      currentInstances,
      saveOptions,
      setInstances,
      store,
      ontology,
    ],
  );

  return { addTag, removeTag };
}
