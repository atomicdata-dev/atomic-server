import { styled, css } from 'styled-components';
import {
  useProperty,
  useResource,
  Datatype,
  Resource,
  urls,
} from '@tomic/react';
import { ResourceInline } from '../views/ResourceInline';
import { useSubjectParam } from '../helpers/useCurrentSubject';
import { FaSort, FaSortDown, FaSortUp } from 'react-icons/fa';
import { Button } from './Button';
import { ValueForm } from './forms/ValueForm';
import { memo } from 'react';

type TableProps = {
  /** A Collection Resource with a filter-value set */
  resource: Resource;
  members: string[];
  /** Array of property URLs to be shown in columns */
  columns: string[];
};

/**
 * A table view for Collections. Header shows properties of the first class of
 * the collection
 */
function Table({ resource, members, columns }: TableProps) {
  // Don't show the shortname, it's already shown in the first row.
  const propsArray = columns.filter(item => item !== urls.properties.shortname);

  if (resource === null) {
    return null;
  }

  return (
    <TableStyled>
      <Header columns={propsArray} />
      {members.length > 0 ? (
        <tbody>
          {members.map(member => {
            return (
              <TableRow propsArray={propsArray} key={member} subject={member} />
            );
          })}
        </tbody>
      ) : (
        <p>This collection is empty</p>
      )}
    </TableStyled>
  );
}

const TableStyled = styled.table`
  overflow-y: auto;
  border-collapse: collapse;
  margin-left: ${p => -p.theme.margin}rem;
  margin-right: ${p => -p.theme.margin}rem;
  margin-bottom: ${p => p.theme.margin}rem;
  width: calc(100% + 2rem);
`;

type HeaderProps = {
  columns: string[];
};

function Header({ columns }: HeaderProps): JSX.Element {
  return (
    <thead>
      <tr>
        <CellHeaderStyled style={{ minWidth: '10rem' }}>
          subject
        </CellHeaderStyled>
        {columns.map(prop => {
          return <HeaderItem key={prop} subject={prop} />;
        })}
      </tr>
    </thead>
  );
}

type HeaderItemProps = {
  subject: string;
};

function HeaderItem({ subject }: HeaderItemProps) {
  const [sortBy, setSortBy] = useSubjectParam('sort_by');
  const [sortDesc, setSortDesc] = useSubjectParam('sort_desc');
  const property = useProperty(subject);
  // Hopefully later we can let users actually edit
  const canSort = !property.isDynamic;

  function handleToggleSort() {
    if (sortBy === subject) {
      if (sortDesc === 'true') {
        setSortDesc(undefined);
      } else {
        setSortDesc('true');
      }
    } else {
      setSortBy(subject);
    }
  }

  const thisPropIsSorted = sortBy === subject;

  let minWidth = '6rem';

  switch (property.datatype) {
    case Datatype.STRING:
    case Datatype.RESOURCEARRAY:
      minWidth = '15rem';
      break;
    case Datatype.MARKDOWN:
      minWidth = '25rem';
      break;
    case Datatype.BOOLEAN:
    case Datatype.INTEGER:
      minWidth = '6rem';
      break;
    default:
      break;
  }

  return (
    <CellHeaderStyled style={{ minWidth }}>
      <ResourceInline subject={subject} />{' '}
      {canSort && (
        <Button
          onClick={handleToggleSort}
          subtle={!thisPropIsSorted}
          icon
          data-test={`sort-${subject}`}
        >
          {thisPropIsSorted ? (
            sortDesc === 'true' ? (
              <FaSortDown />
            ) : (
              <FaSortUp />
            )
          ) : (
            <FaSort />
          )}
        </Button>
      )}
    </CellHeaderStyled>
  );
}

type RowProps = {
  subject: string;
  propsArray: string[];
};

const TableRow = memo(function TableRow({ subject, propsArray }: RowProps) {
  const resource = useResource(subject, {
    // We don't need to fetch all members for Collections when looking at a Table view.
    allowIncomplete: true,
  });

  if (resource === null) {
    return null;
  }

  return (
    <RowStyled about={subject}>
      <CellStyled>
        <ResourceInline subject={subject} />
      </CellStyled>
      {propsArray.map(prop => {
        return <Cell key={prop} resource={resource} prop={prop} />;
      })}
    </RowStyled>
  );
});

const RowStyled = styled.tr`
  background-color: ${p => p.theme.colors.bg};
  border-top: solid 1px ${props => props.theme.colors.bg2};

  &:last-child {
    border-bottom: solid 1px ${props => props.theme.colors.bg2};
  }
`;

const CellContainer = styled.div`
  overflow: auto;
  /* Not a pretty solution, but it's better than having really large cells. */
  max-height: 5rem;
  max-width: 40rem;
`;

type CellProps = {
  prop: string;
  resource: Resource;
};

function Cell({ resource, prop: propUrl }: CellProps): JSX.Element {
  return (
    <CellStyled>
      <CellContainer>
        <ValueForm
          key={propUrl}
          resource={resource}
          propertyURL={propUrl}
          noMargin
        />
      </CellContainer>
    </CellStyled>
  );
}

const cellStyles = css`
  padding: ${p => p.theme.margin / 2}rem;
  padding-left: ${p => p.theme.margin}rem;
  vertical-align: top;

  &:last-child {
    width: 100% !important;
    max-width: 100% !important;
  }
`;

const CellHeaderStyled = styled.th`
  text-align: left;
  ${cellStyles}
  font-weight: bold;
  white-space: nowrap;
`;

const CellStyled = styled.td`
  ${cellStyles}
`;

export default Table;
