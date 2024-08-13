import {
  Resource,
  useResource,
  useStore,
  Server,
  unknownSubject,
  core,
  Core,
} from '@tomic/react';
import { useSettings } from '../helpers/AppSettings';
import { useCallback } from 'react';
import { sortSubjectList } from '../views/OntologyPage/sortSubjectList';

export function useAddToOntology(ontologySubject?: string) {
  const store = useStore();
  const { drive: driveSubject } = useSettings();
  const drive = useResource<Server.Drive>(driveSubject);

  const ontology = useResource<Core.Ontology>(
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
        await ontology.set(
          core.properties.classes,
          await sortSubjectList(store, [
            ...(ontology.props.classes ?? []),
            resource.subject,
          ]),
        );
      } else if (resource.hasClasses(core.classes.property)) {
        await ontology.set(
          core.properties.properties,
          await sortSubjectList(store, [
            ...(ontology.props.properties ?? []),
            resource.subject,
          ]),
        );
      } else {
        ontology.push(core.properties.instances, [resource.subject], true);
      }

      await ontology.save();
    },
    [store, drive, ontology],
  );
}
