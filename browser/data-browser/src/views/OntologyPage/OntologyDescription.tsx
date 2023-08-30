import {
  Resource,
  useString,
  urls,
  useProperty,
  useCanWrite,
} from '@tomic/react';
import React from 'react';
import Markdown from '../../components/datatypes/Markdown';
import InputMarkdown from '../../components/forms/InputMarkdown';

interface OntologyDescriptionProps {
  resource: Resource;
  edit: boolean;
}

export function OntologyDescription({
  resource,
  edit,
}: OntologyDescriptionProps): JSX.Element {
  const [description] = useString(resource, urls.properties.description);
  const property = useProperty(urls.properties.description);

  const [canEdit] = useCanWrite(resource);

  if (!edit || !canEdit) {
    return <Markdown text={description ?? ''} />;
  }

  return <InputMarkdown commit resource={resource} property={property} />;
}
