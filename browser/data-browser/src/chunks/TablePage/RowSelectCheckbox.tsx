import { useContext, type JSX } from 'react';
import {
  unknownSubject,
  useMemberFromCollection,
  type Collection,
} from '@tomic/react';
import { styled } from 'styled-components';
import { FaCheck } from 'react-icons/fa6';
import { TablePageContext } from './tablePageContext';

type RowSelectCheckboxProps = { index: number } & (
  | { collection: Collection; subject?: undefined }
  | { subject: string; collection?: undefined }
);

/**
 * The tick box in a row's header cell. Hidden until the row is hovered, unless
 * a row is already ticked: then every row shows one ("select mode").
 *
 * Give it the row's `subject` when the caller already knows it (rows added this
 * session); otherwise the subject is looked up in the `collection` by `index`.
 */
export function RowSelectCheckbox(
  props: RowSelectCheckboxProps,
): JSX.Element | null {
  return props.collection ? (
    <CollectionRowCheckbox collection={props.collection} index={props.index} />
  ) : (
    <SubjectCheckbox subject={props.subject} index={props.index} />
  );
}

function CollectionRowCheckbox({
  collection,
  index,
}: {
  collection: Collection;
  index: number;
}): JSX.Element | null {
  const { subject } = useMemberFromCollection(collection, index);

  return subject === unknownSubject ? null : (
    <SubjectCheckbox subject={subject} index={index} />
  );
}

function SubjectCheckbox({
  subject,
  index,
}: {
  subject: string;
  index: number;
}): JSX.Element {
  const { selectedRows, toggleRowSelected } = useContext(TablePageContext);

  return (
    <span data-row-select data-active={selectedRows.size > 0}>
      <Box
        type='button'
        role='checkbox'
        aria-checked={selectedRows.has(subject)}
        aria-label={`Select row ${index + 1}`}
        // The header cell selects itself on mouse down; a tick shouldn't.
        onMouseDown={e => e.stopPropagation()}
        onClick={e => {
          e.stopPropagation();
          toggleRowSelected(subject);
        }}
      >
        <FaCheck />
      </Box>
    </span>
  );
}

// Not an `<input type=checkbox>`: the grid's keyboard handling and its tests
// look for the first `input` inside the grid to find the cell editor.
const Box = styled.button`
  display: grid;
  place-items: center;
  flex-shrink: 0;
  width: 1rem;
  height: 1rem;
  padding: 0;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: 3px;
  background-color: ${p => p.theme.colors.bg};
  color: transparent;
  font-size: 0.6rem;
  cursor: pointer;

  &[aria-checked='true'] {
    border-color: ${p => p.theme.colors.main};
    background-color: ${p => p.theme.colors.main};
    color: ${p => p.theme.colors.bg};
  }

  &:hover:not([aria-checked='true']) {
    border-color: ${p => p.theme.colors.main};
  }
`;
