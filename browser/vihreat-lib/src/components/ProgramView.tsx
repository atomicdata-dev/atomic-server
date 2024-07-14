import Markdown from 'react-markdown';
import { useArray, useDate, useString, Resource } from '@tomic/react';
import { Program, ontology } from '../ontologies/ontology';
import { Body } from './program/Body';
import { FrontMatter } from './program/FrontMatter';
import { Title } from './program/Title';

interface ProgramViewProps {
  resource: Resource<Program>;
}

export function ProgramView({ resource }: ProgramViewProps): JSX.Element {
  const [title] = useString(resource, ontology.properties.title);
  const approvedOn = useDate(resource, ontology.properties.approvedon);
  const [elements] = useArray(resource, ontology.properties.elements);

  if (title !== undefined && elements !== undefined) {
    return (
      <div className='vo-container'>
        <Title title={title} />
        <FrontMatter approvedOn={approvedOn} />
        <Body elements={elements} />
      </div>
    );
  } else {
    return (
      <>
        <p>Failed to load resource {resource.subject}. Is the server running?</p>;
      </>
    );
  }
}
