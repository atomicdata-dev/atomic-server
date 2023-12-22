import { ButtonSection } from './ButtonSection';
import { Core, core, useResource, useServerSearch } from '@tomic/react';
import { ClassButton } from './ClassButton';
import { FC } from 'react';
import { useSettings } from '../../helpers/AppSettings';

interface OntologySectionsProps {
  parent: string;
}

export function OntologySections({
  parent,
}: OntologySectionsProps): JSX.Element {
  const { drive } = useSettings();

  const { results } = useServerSearch('', {
    filters: {
      [core.properties.isA]: core.classes.ontology,
    },
    parents: [drive],
    allowEmptyQuery: true,
    limit: 100,
  });

  return (
    <>
      {results.map(subject => (
        <OntologySection subject={subject} key={subject} parent={parent} />
      ))}
    </>
  );
}

interface OntologySectionProps {
  subject: string;
  parent: string;
}

const OntologySection: FC<OntologySectionProps> = ({ subject, parent }) => {
  const ontology = useResource<Core.Ontology>(subject);
  const classes = ontology.props.classes ?? [];

  if (classes.length === 0) {
    return null;
  }

  return (
    <ButtonSection title={ontology.title}>
      {classes.map(classType => (
        <ClassButton key={classType} classType={classType} parent={parent} />
      ))}
    </ButtonSection>
  );
};
