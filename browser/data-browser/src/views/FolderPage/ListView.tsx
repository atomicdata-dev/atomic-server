import {
  core,
  Resource,
  useCreatedBy,
  useCreatedAt,
  useResource,
  useString,
  useTitle,
} from '@tomic/react';

import { styled } from 'styled-components';
import { AtomicLink } from '../../components/AtomicLink';
import { CommitDetail } from '../../components/CommitDetail';
import { ViewProps } from './FolderDisplayStyle';
import { getIconForClass } from '../../helpers/iconMap';
import { QuickCreateRow } from '../../components/NewInstanceButton';
import { CommentCountBadge } from '../../components/CommentCountBadge';

import type { JSX } from 'react';

export function ListView({
  subResources,
  showNewButton,
  basic,
  parent,
}: ViewProps): JSX.Element {
  return (
    <Wrapper>
      <StyledTable data-test='folder-list'>
        <>
          <thead>
            <tr>
              <th>
                <TitleHeaderWrapper>Title</TitleHeaderWrapper>
              </th>
              <ClassCell as='th'>Class</ClassCell>
              {!basic && <AlignRight as='th'>Created</AlignRight>}
            </tr>
          </thead>
          <tbody>
            {Array.from(subResources.values()).map(resource => (
              <TableRow key={resource.subject}>
                <td>
                  <Title resource={resource} />
                </td>
                <ClassCell>
                  <ClassType resource={resource} />
                </ClassCell>
                {!basic && (
                  <AlignRight>
                    <Created resource={resource} />
                  </AlignRight>
                )}
              </TableRow>
            ))}
          </tbody>
        </>
      </StyledTable>
      {showNewButton && (
        <QuickCreateRowWrapper>
          <QuickCreateRow parent={parent} />
        </QuickCreateRowWrapper>
      )}
    </Wrapper>
  );
}

interface CellProps {
  resource: Resource;
}

function Title({ resource }: CellProps): JSX.Element {
  const [title] = useTitle(resource);
  const [classType] = useString(resource, core.properties.isA);
  const Icon = getIconForClass(classType ?? '');

  return (
    <TitleWrapper>
      <IconWrapper>
        <Icon />
      </IconWrapper>
      <AtomicLink subject={resource.subject}>{title}</AtomicLink>
      <CommentCountBadge subject={resource.subject} />
    </TitleWrapper>
  );
}

function Created({ resource }: CellProps): JSX.Element {
  const createdAt = useCreatedAt(resource);
  const createdBy = useCreatedBy(resource);

  return (
    <LinkWrapper>
      <CommitDetail short createdAt={createdAt} createdBy={createdBy} />
    </LinkWrapper>
  );
}

function ClassType({ resource }: CellProps): JSX.Element {
  const [classType] = useString(resource, core.properties.isA);
  const classTypeResource = useResource(classType);
  const [title] = useTitle(classTypeResource);

  if (resource.loading) {
    return <LinkWrapper></LinkWrapper>;
  }

  return (
    <LinkWrapper>
      <AtomicLink subject={classType}>{title}</AtomicLink>
    </LinkWrapper>
  );
}

const Wrapper = styled.div`
  --icon-width: 1rem;
  --icon-title-spacing: 1rem;
  --cell-padding: 0.4rem;
`;

const StyledTable = styled.table`
  text-align: left;
  border-collapse: collapse;
  width: 100%;
  th {
    padding-bottom: 1rem;
  }

  th:last-child {
    padding-right: 2rem;
  }

  td,
  th {
    border: none !important;
  }
`;

const IconWrapper = styled.span`
  width: var(--icon-width);
  display: inline-flex;
  align-items: center;
`;

const TitleWrapper = styled.div`
  display: flex;
  align-items: center;
  gap: var(--icon-title-spacing);

  svg {
    color: ${p => p.theme.colors.textLight};
  }
`;

const TitleHeaderWrapper = styled.span`
  margin-inline-start: calc(
    var(--icon-width) + var(--icon-title-spacing) + var(--cell-padding)
  );
`;

const AlignRight = styled.td`
  text-align: right;
`;

const LinkWrapper = styled.span`
  a {
    color: ${p => p.theme.colors.textLight};
  }
`;

const TableRow = styled.tr`
  &:nth-child(odd) {
    td {
      background-color: ${p => p.theme.colors.bg1};
    }

    td:first-child {
      border-top-left-radius: ${p => p.theme.radius};
      border-bottom-left-radius: ${p => p.theme.radius};
    }

    td:last-child {
      border-top-right-radius: ${p => p.theme.radius};
      border-bottom-right-radius: ${p => p.theme.radius};
    }
  }

  td {
    padding: var(--cell-padding);
  }
`;

const ClassCell = styled.td`
  @container (max-width: 500px) {
    display: none;
  }
`;

const QuickCreateRowWrapper = styled.div`
  margin-top: 1rem;
  margin-inline-start: calc(
    var(--icon-width) + var(--icon-title-spacing) + var(--cell-padding)
  );
`;
