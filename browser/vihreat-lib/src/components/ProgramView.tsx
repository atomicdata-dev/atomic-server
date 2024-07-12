import {
  core,
  useArray,
  useDate,
  useNumber,
  useResource,
  useString,
  Resource,
} from '@tomic/react';
import { Program, ontology } from '../ontologies/ontology';
import Markdown from 'react-markdown';

interface ProgramViewProps {
  resource: Resource<Program>;
}

export function ProgramView({ resource }: ProgramViewProps): JSX.Element {
  const [title] = useString(resource, ontology.properties.title);
  const approvedOn = useDate(resource, ontology.properties.approvedon);
  const [elements] = useArray(resource, ontology.properties.elements);

  if (title !== undefined && elements !== undefined) {
    return (
      <div className='vo-program'>
        <Metadata title={title} approvedOn={approvedOn} />
        <Body elements={elements} />
      </div>
    );
  } else {
    return (
      <>
        <p>Failed to load resource; is the server running?</p>
      </>
    );
  }
}

interface MetadataProps {
  title: string;
  approvedOn: Date | undefined;
}

function Metadata({ approvedOn, title }: MetadataProps): JSX.Element {
  if (approvedOn) {
    const approvedOnStr = approvedOn.toLocaleString('fi-FI', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });

    return (
      <div className='vo-program-meta'>
        <h1>{title}</h1>
        <p>Hyväksytty {approvedOnStr}</p>
      </div>
    );
  } else {
    return (
      <>
        <h1>{title}</h1>
      </>
    );
  }
}

interface BodyProps {
  elements: string[];
}

function Body({ elements }: BodyProps): JSX.Element {
  return (
    <div className='vo-program-body'>
      {elements.map(subject => (
        <Element subject={subject} key={subject} />
      ))}
    </div>
  );
}

interface ElementProps {
  subject: string;
}

function Element({ subject }: ElementProps): JSX.Element {
  const resource = useResource(subject);
  const [klass] = useString(resource, core.properties.isA);

  switch (klass!) {
    case ontology.classes.paragraph:
      return <Paragraph subject={subject} />;
    case ontology.classes.title:
      return <Title subject={subject} />;
    case ontology.classes.actionitem:
      return <ActionItem subject={subject} />;
    default:
      return <Unknown subject={subject} />;
  }
}

function Paragraph({ subject }: ElementProps): JSX.Element {
  const resource = useResource(subject);
  const [text] = useString(resource, ontology.properties.text);

  if (text !== undefined) {
    return <Markdown>{text}</Markdown>;
  } else {
    return (
      <p>
        <strong>Failed to get element text!</strong>
      </p>
    );
  }
}

function Title({ subject }: ElementProps): JSX.Element {
  const resource = useResource(subject);
  const [text] = useString(resource, ontology.properties.text);
  const [level] = useNumber(resource, ontology.properties.titlelevel);

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
  const [text] = useString(resource, ontology.properties.text);

  return (
    <ul>
      <li>{text}</li>
    </ul>
  );
}

function Unknown({ subject }: ElementProps): JSX.Element {
  return <p>{subject}</p>;
}
