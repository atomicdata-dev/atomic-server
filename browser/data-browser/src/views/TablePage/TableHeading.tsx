import {
  Datatype,
  Property,
  Resource,
  useResource,
  useTitle,
} from '@tomic/react';
import React from 'react';
import { FaAngleDown, FaAngleUp, FaAtom } from 'react-icons/fa';
import { styled } from 'styled-components';
import { dataTypeIconMap } from './dataTypeMaps';
import { TableHeadingMenu } from './TableHeadingMenu';
import { TablePageContext } from './tablePageContext';
import { IconType } from 'react-icons';
import { TableSorting } from './tableSorting';

export interface TableHeadingProps {
  column: Property;
}

function getIcon(
  propResource: Resource,
  sorting: TableSorting,
  dataType: Datatype,
): IconType {
  if (sorting.prop === propResource.getSubject()) {
    return sorting.sortDesc ? FaAngleDown : FaAngleUp;
  }

  return dataTypeIconMap.get(dataType) ?? FaAtom;
}

export function TableHeading({ column }: TableHeadingProps): JSX.Element {
  const propResource = useResource(column.subject);
  const [title] = useTitle(propResource);
  const { setSortBy, sorting } = React.useContext(TablePageContext);

  const Icon = getIcon(propResource, sorting, column.datatype);
  const isSorted = sorting.prop === propResource.getSubject();

  return (
    <>
      <Wrapper>
        <Icon />
        <NameButton
          onClick={() => setSortBy(propResource.getSubject())}
          bold={isSorted}
        >
          {title || column.shortname}
        </NameButton>
      </Wrapper>
      <TableHeadingMenu resource={propResource} />
    </>
  );
}

const Wrapper = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;

  svg {
    color: currentColor;
  }
`;

interface NameButtonProps {
  bold?: boolean;
}

const NameButton = styled.button<NameButtonProps>`
  background: none;
  border: none;
  color: currentColor;
  cursor: pointer;
  font-weight: ${p => (p.bold ? 'bold' : 'normal')};
  // TODO: make this dynamic, don't overflow on names, use grid flex?
  max-width: 8rem;
  overflow: hidden;
  text-overflow: ellipsis;
`;
