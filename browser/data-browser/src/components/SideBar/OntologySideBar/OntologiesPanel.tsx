import { styled } from 'styled-components';
import {
  Collection,
  unknownSubject,
  urls,
  useCollection,
  useMemberFromCollection,
} from '@tomic/react';
import { SideBarItem } from '../SideBarItem';
import { Row } from '../../Row';
import { AtomicLink } from '../../AtomicLink';
import { getIconForClass } from '../../../views/FolderPage/iconMap';
import { ScrollArea } from '../../ScrollArea';
import { ErrorLook } from '../../ErrorLook';

export function OntologiesPanel(): JSX.Element | null {
  const { collection } = useCollection({
    property: urls.properties.isA,
    value: urls.classes.ontology,
  });

  return (
    <Wrapper>
      <StyledScrollArea>
        {[...Array(collection.totalMembers).keys()].map(index => (
          <Item key={index} collection={collection} index={index} />
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
  height: 10rem;
  overflow-x: hidden;
`;

interface ItemProps {
  index: number;
  collection: Collection;
}

function Item({ index, collection }: ItemProps): JSX.Element {
  const resource = useMemberFromCollection(collection, index);

  const Icon = getIconForClass(urls.classes.ontology);

  if (resource.loading) {
    return <div>loading</div>;
  }

  if (resource.error || resource.getSubject() === unknownSubject) {
    return (
      <SideBarItem>
        <ErrorLook>Invalid Resource</ErrorLook>
      </SideBarItem>
    );
  }

  return (
    <StyledLink subject={resource.getSubject()} clean>
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
