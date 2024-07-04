import * as React from 'react';
import { core, useArray, useDate, useNumber, useStore, useString, useResource } from '@tomic/react';
import { vihreat } from './vihreat';

import { ResourcePageProps } from '../views/ResourcePage';
import Markdown from '../components/datatypes/Markdown';

function organizeElements(subjects: string[]) {

}

export function ProgramPage({ resource }: ResourcePageProps): JSX.Element {
  const store = useStore();
  const [elements] = useArray(resource, vihreat.properties.elements);
  const [title] = useString(resource, vihreat.properties.title);
  const approvedOn = useDate(resource, vihreat.properties.approvedOn);

  return (
    <div className='vihreat-ohjelma'>
      <h1 className='vihreat-otsikko'>{title}</h1>
      {
        (approvedOn) ?
          <p>Hyväksytty {approvedOn!.toLocaleString('fi-FI', { year: 'numeric', month: 'long', day: 'numeric' })}</p> : ""
      }
      {elements.map(subject => (
        <Element subject={subject} key={subject} />
      ))}
    </div>
  );
}

export default ProgramPage;


interface ElementProps {
  subject: string;
}
function Element({ subject }: ElementProps): JSX.Element {
  const resource = useResource(subject);
  const [klass] = useString(resource, core.properties.isA);
  switch (klass!) {
    case vihreat.classes.paragraph:
      return <Paragraph subject={subject} />;
    case vihreat.classes.title:
      return <Title subject={subject} />;
    case vihreat.classes.actionItem:
      return <ActionItem subject={subject} />;
    default:
      return <Unknown subject={subject} />;
  }
}

function Paragraph({ subject }: ElementProps): JSX.Element {
  const resource = useResource(subject);
  const [text] = useString(resource, vihreat.properties.text);
  return <Markdown text={text || ''} />;
}

function Title({ subject }: ElementProps): JSX.Element {
  const resource = useResource(subject);
  const [text] = useString(resource, vihreat.properties.text);
  const [level] = useNumber(resource, vihreat.properties.titleLevel);
  switch (level) {
    case 1:
    default:
      return <h1>{text}</h1>;
    case 2:
      return <h2>{text}</h2>;
    case 3:
      return <h3>{text}</h3>;
    case 4:
      return <h4>{text}</h4>;
    case 5:
      return <h5>{text}</h5>;
    case 6:
      return <h6>{text}</h6>;
  }
}

function ActionItem({ subject }: ElementProps): JSX.Element {
  const resource = useResource(subject);
  const [text] = useString(resource, vihreat.properties.text);
  return <ul><li>{text}</li></ul>;
}

function Unknown({ subject }: ElementProps): JSX.Element {
  return <></>;
}