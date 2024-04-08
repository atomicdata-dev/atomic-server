import {
  Resource,
  useResource,
  useStore,
  Server,
  unknownSubject,
  core,
} from '@tomic/react';
import { useSettings } from '../helpers/AppSettings';
import { useCallback } from 'react';

export function useAddToOntology(ontologySubject?: string) {
  const store = useStore();
  const { drive: driveSubject } = useSettings();
  const drive = useResource<Server.Drive>(driveSubject);

  const ontology = useResource(
    ontologySubject ?? drive.props.defaultOntology ?? unknownSubject,
  );

  return useCallback(
    async (resource: Resource) => {
      if (ontology.subject === unknownSubject) {
        await resource.set(core.properties.parent, driveSubject);
        resource.save();

        return;
      }

      await resource.set(core.properties.parent, ontology.subject);
      await resource.save();

      if (resource.hasClasses(core.classes.class)) {
        ontology.push(core.properties.classes, [resource.subject], true);
      } else if (resource.hasClasses(core.classes.property)) {
        ontology.push(core.properties.properties, [resource.subject], true);
      } else {
        ontology.push(core.properties.instances, [resource.subject], true);
      }

      await ontology.save();
    },
    [store, drive, ontology],
  );
}
