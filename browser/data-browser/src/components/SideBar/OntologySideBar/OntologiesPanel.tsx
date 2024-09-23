import { styled } from 'styled-components';
import {
  core,
  removeCachedSearchResults,
  unknownSubject,
  useResource,
  useStore,
} from '@tomic/react';
import { SideBarItem } from '../SideBarItem';
import { Row } from '../../Row';
import { AtomicLink } from '../../AtomicLink';
import { getIconForClass } from '../../../helpers/iconMap';
import { ScrollArea } from '../../ScrollArea';
import { ErrorLook } from '../../ErrorLook';
import { useCallback, useEffect, useState } from 'react';
import { useSettings } from '../../../helpers/AppSettings';

export function OntologiesPanel(): JSX.Element | null {
  const store = useStore();
  const [ontologies, setOntologies] = useState<string[]>([]);
  const { drive } = useSettings();

  const search = useCallback(async () => {
    removeCachedSearchResults(store);

    const result = await store.search('', {
      filters: {
        [core.properties.isA]: core.classes.ontology,
      },
      parents: drive,
    });

    setOntologies(result);
  }, [store, drive]);

  useEffect(() => {
    search();

    // If the drive was just created we need to wait for search to index the new ontology. So we search again after 5 seconds.
    setTimeout(() => {
      search();
    }, 5000);
  }, [drive, search]);

  return (
    <Wrapper>
      <StyledScrollArea key={drive}>
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
