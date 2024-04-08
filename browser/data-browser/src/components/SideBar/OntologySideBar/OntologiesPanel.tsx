import { styled } from 'styled-components';
import { core, unknownSubject, useResource, useStore } from '@tomic/react';
import { SideBarItem } from '../SideBarItem';
import { Row } from '../../Row';
import { AtomicLink } from '../../AtomicLink';
import { getIconForClass } from '../../../views/FolderPage/iconMap';
import { ScrollArea } from '../../ScrollArea';
import { ErrorLook } from '../../ErrorLook';
import { useEffect, useState } from 'react';
import { useSettings } from '../../../helpers/AppSettings';

export function OntologiesPanel(): JSX.Element | null {
  const store = useStore();
  const [ontologies, setOntologies] = useState<string[]>([]);
  const { drive } = useSettings();

  useEffect(() => {
    store
      .search('', {
        filters: {
          [core.properties.isA]: core.classes.ontology,
        },
        parents: drive,
      })
      .then(setOntologies);
  }, [store]);

  return (
    <Wrapper>
      <StyledScrollArea>
        {ontologies.map(subject => (
          <Item key={subject} subject={subject} />
        ))}
      </StyledScrollArea>
    </Wrapper>
  );
}

const Wrapper = styled.div`
  padding-top: 0;
  max-height: 10rem;
  overflow: hidden;
`;

const StyledScrollArea = styled(ScrollArea)`
  max-height: 10rem;
  overflow-x: hidden;
`;

interface ItemProps {
  subject: string;
}

function Item({ subject }: ItemProps): JSX.Element {
  const resource = useResource(subject);

  const Icon = getIconForClass(core.classes.ontology);

  if (resource.loading) {
    return <div>loading</div>;
  }

  if (resource.error || resource.subject === unknownSubject) {
    return (
      <SideBarItem>
        <ErrorLook>Invalid Resource</ErrorLook>
      </SideBarItem>
    );
  }

  return (
    <StyledLink subject={subject} clean>
      <SideBarItem>
        <Row gap='1ch' center>
          <Icon />
          {resource.title}
        </Row>
      </SideBarItem>
    </StyledLink>
  );
}

const StyledLink = styled(AtomicLink)`
  flex: 1;
  overflow: hidden;
  white-space: nowrap;
`;
