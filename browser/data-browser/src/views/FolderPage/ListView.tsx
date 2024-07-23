import {
  properties,
  Resource,
  useResource,
  useString,
  useTitle,
} from '@tomic/react';

import { styled } from 'styled-components';
import { AtomicLink } from '../../components/AtomicLink';
import { CommitDetail } from '../../components/CommitDetail';
import { ViewProps } from './FolderDisplayStyle';
import { getIconForClass } from './iconMap';
import { FaPlus } from 'react-icons/fa';
import { Button } from '../../components/Button';

export function ListView({
  subResources,
  onNewClick,
  showNewButton,
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
              <AlignRight as='th'>Last Modified</AlignRight>
            </tr>
          </thead>
          <tbody>
            {Array.from(subResources.values()).map(resource => (
              <TableRow key={resource.getSubject()}>
                <td>
                  <Title resource={resource} />
                </td>
                <ClassCell>
                  <ClassType resource={resource} />
                </ClassCell>
                <AlignRight>
                  <LastCommit resource={resource} />
                </AlignRight>
              </TableRow>
            ))}
          </tbody>
        </>
      </StyledTable>
      {showNewButton && (
        <NewButton clean onClick={onNewClick} data-testid='new-resource-folder'>
          <span>
            <FaPlus /> New Resource
          </span>
        </NewButton>
      )}
    </Wrapper>
  );
}

interface CellProps {
  resource: Resource;
}

function Title({ resource }: CellProps): JSX.Element {
  const [title] = useTitle(resource);
  const [classType] = useString(resource, properties.isA);
  const Icon = getIconForClass(classType ?? '');

  return (
    <TitleWrapper>
      <IconWrapper>
        <Icon />
      </IconWrapper>
      <AtomicLink subject={resource.getSubject()}>{title}</AtomicLink>
    </TitleWrapper>
  );
}

function LastCommit({ resource }: CellProps): JSX.Element {
  const [commit] = useString(resource, properties.commit.lastCommit);

  return (
    <LinkWrapper>
      <CommitDetail commitSubject={commit} />
    </LinkWrapper>
  );
}

function ClassType({ resource }: CellProps): JSX.Element {
  const [classType] = useString(resource, properties.isA);
  const classTypeResource = useResource(classType);
  const [title] = useTitle(classTypeResource);

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
  width: var(--container-width);
  margin-inline: auto;
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

const NewButton = styled(Button)`
  margin-top: 1rem;
  margin-inline-start: calc(
    var(--icon-width) + var(--icon-title-spacing) + var(--cell-padding)
  );
  > span {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
`;
