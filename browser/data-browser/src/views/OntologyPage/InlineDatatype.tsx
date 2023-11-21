import {
  Resource,
  useString,
  urls,
  reverseDatatypeMapping,
  unknownSubject,
  useResource,
} from '@tomic/react';
import { ResourceInline } from '../ResourceInline';
import { toAnchorId } from './toAnchorId';
import { useOntologyContext } from './OntologyContext';

interface TypeSuffixProps {
  resource: Resource;
}

export function InlineDatatype({ resource }: TypeSuffixProps): JSX.Element {
  const [datatype] = useString(resource, urls.properties.datatype);
  const [classType] = useString(resource, urls.properties.classType);
  const { hasClass } = useOntologyContext();

  const name = reverseDatatypeMapping[datatype ?? unknownSubject];

  if (!classType) {
    return <span>{name}</span>;
  }

  return (
    <span>
      {name}
      {'<'}
      {hasClass(classType) ? (
        <LocalLink subject={classType} />
      ) : (
        <ResourceInline subject={classType} />
      )}
      {'>'}
    </span>
  );
}

interface LocalLinkProps {
  subject: string;
}

function LocalLink({ subject }: LocalLinkProps): JSX.Element {
  const resource = useResource(subject);

  return <a href={`#${toAnchorId(subject)}`}>{resource.title}</a>;
}
