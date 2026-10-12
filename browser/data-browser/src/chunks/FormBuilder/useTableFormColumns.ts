import { core, useArray, useResource, useResources } from '@tomic/react';

export function useTableFormColumns(dataClassSubject: string) {
  const dataClass = useResource(dataClassSubject);
  const [requires] = useArray(dataClass, core.properties.requires);
  const [recommends] = useArray(dataClass, core.properties.recommends);
  const subjects = [...new Set([...requires, ...recommends])];
  const resources = useResources(subjects);

  return {
    dataClass,
    requires,
    columns: subjects.flatMap(s => {
      const property = resources.get(s);

      return property && !property.loading ? [property] : [];
    }),
    loading:
      dataClass.loading ||
      subjects.some(s => !resources.get(s) || resources.get(s)?.loading),
  };
}
