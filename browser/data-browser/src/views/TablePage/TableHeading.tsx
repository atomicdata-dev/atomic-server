import {
  Core,
  Datatype,
  Property,
  Resource,
  useResource,
  useTitle,
} from '@tomic/react';

import { FaAngleDown, FaAngleUp, FaAtom } from 'react-icons/fa';
import { FaGripVertical } from 'react-icons/fa6';
import { styled } from 'styled-components';
import { dataTypeIconMap } from './dataTypeMaps';
import { TableHeadingMenu } from './TableHeadingMenu';
import { TablePageContext } from './tablePageContext';
import { IconType } from 'react-icons';
import { TableSorting } from './tableSorting';
import { useContext, useState } from 'react';
import { TableHeadingComponent } from '../../components/TableEditor/TableHeader';

function getIcon(
  propResource: Resource,
  sorting: TableSorting,
  hoverOrFocus: boolean,
  dataType: Datatype,
): IconType {
  if (sorting.prop === propResource.getSubject()) {
    return sorting.sortDesc ? FaAngleDown : FaAngleUp;
  }

  if (hoverOrFocus) {
    return FaGripVertical;
  }

  return dataTypeIconMap.get(dataType) ?? FaAtom;
}

export const TableHeading: TableHeadingComponent<Property> = ({
  column,
  dragListeners,
  dragAttributes,
}): JSX.Element => {
  const [hoverOrFocus, setHoverOrFocus] = useState(false);

  const propResource = useResource(column.subject);
  const [title] = useTitle(propResource);
  const { setSortBy, sorting, tableClassSubject } =
    useContext(TablePageContext);
  const tableClass = useResource<Core.Class>(tableClassSubject);

  const isRequired = (tableClass.props.requires ?? []).includes(column.subject);

  const Icon = getIcon(propResource, sorting, hoverOrFocus, column.datatype);
  const isSorted = sorting.prop === propResource.subject;

  const text = `${title || column.shortname}${isRequired ? '*' : ''}`;

  return (
    <>
      <Wrapper
        onMouseEnter={() => setHoverOrFocus(true)}
        onMouseLeave={() => setHoverOrFocus(false)}
        onFocus={() => setHoverOrFocus(true)}
        onBlur={() => setHoverOrFocus(false)}
      >
        <DragIconButton {...dragListeners} {...dragAttributes}>
          <Icon title='Drag column' />
        </DragIconButton>
        <NameButton
          onClick={() => setSortBy(propResource.subject)}
          bold={isSorted}
          title={text}
        >
          <span aria-hidden>{text}</span>
        </NameButton>
        <TableHeadingMenu resource={propResource} />
      </Wrapper>
    </>
  );
};

const Wrapper = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  width: 100%;
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
  overflow: hidden;
  text-overflow: ellipsis;
  padding: 0;
`;

const DragIconButton = styled.button`
  background: none;
  color: currentColor;
  display: flex;
  align-items: center;
  border: none;
  height: 1rem;
  padding: 0;
  cursor: grab;

  &:active {
    cursor: grabbing;
  }
  svg {
    color: currentColor;
    max-width: 1rem;
    min-width: 1rem;
    flex: 1;
  }
`;
