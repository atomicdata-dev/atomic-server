import { Collection, useCollectionPage } from '@tomic/react';

import { styled } from 'styled-components';
import { Details } from '../Details';
import { UsageRow } from './UsageRow';
import { Column, Row } from '../Row';
import { useState } from 'react';
import { FaChevronLeft, FaChevronRight } from 'react-icons/fa6';
import { IconButton } from '../IconButton/IconButton';

interface UsageCardProps {
  collection: Collection;
  title: string | React.ReactNode;
  initialOpenState?: boolean;
}

export function UsageCard({
  collection,
  title,
  initialOpenState = false,
}: UsageCardProps): JSX.Element {
  const [page, setPage] = useState(0);
  const [isOpen, setIsOpen] = useState(initialOpenState);
  const members = useCollectionPage(collection, page);

  const PageButtons = (
    <Row center>
      <IconButton
        title='Previous page'
        onClick={() => setPage(p => p - 1)}
        disabled={page === 0}
      >
        <FaChevronLeft />
      </IconButton>
      <PageNumber>{page + 1}</PageNumber>
      <IconButton
        title='Next page'
        onClick={() => setPage(p => p + 1)}
        disabled={page === collection.totalPages - 1}
      >
        <FaChevronRight />
      </IconButton>
    </Row>
  );

  return (
    <DetailsCard>
      <Details
        noIndent
        title={
          <Row justify='space-between'>
            <span>{title}</span>
            {isOpen && PageButtons}
          </Row>
        }
        initialState={initialOpenState}
        onStateToggle={setIsOpen}
      >
        <ContentWrapper>
          <List>
            {/* We need to filter out duplicate members because react will do weird things when duplicate keys are present */}
            {Array.from(new Set(members)).map(s => (
              <UsageRow subject={s} key={s} />
            ))}
          </List>
          <Row justify='end'>{PageButtons}</Row>
        </ContentWrapper>
      </Details>
    </DetailsCard>
  );
}

const DetailsCard = styled.div`
  border: 1px solid ${({ theme }) => theme.colors.bg2};
  border-radius: ${({ theme }) => theme.radius};
  padding: ${({ theme }) => theme.margin}rem;

  background-color: ${({ theme }) => theme.colors.bg};
`;

const List = styled.ul`
  margin: 0;
  padding: 0;
`;

const ContentWrapper = styled(Column)`
  margin-top: ${({ theme }) => theme.margin}rem;
`;

const PageNumber = styled.span`
  color: ${({ theme }) => theme.colors.textLight};
`;
