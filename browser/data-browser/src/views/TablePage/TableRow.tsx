import { memo, useEffect, useState } from 'react';
import {
  Collection,
  DataBrowser,
  Property,
  Resource,
  core,
  unknownSubject,
  useMemberFromCollection,
  useResource,
} from '@tomic/react';
import { TableCell } from './TableCell';
import { randomSubject } from '../../helpers/randomString';
import { styled, keyframes } from 'styled-components';

interface TableRowProps {
  collection: Collection;
  index: number;
  columns: Property[];
}

const TableCellMemo = memo(TableCell);

export function TableRow({
  collection,
  index,
  columns,
}: TableRowProps): JSX.Element {
  const resource = useMemberFromCollection(collection, index);

  if (resource.subject === unknownSubject) {
    return (
      <>
        {columns.map((column, i) => (
          <Loader key={column.subject} delay={i * 100} title='loading' />
        ))}
      </>
    );
  }

  return (
    <>
      {columns.map((column, cIndex) => (
        <TableCellMemo
          key={column.subject}
          rowIndex={index}
          columnIndex={cIndex + 1}
          resource={resource}
          property={column}
        />
      ))}
    </>
  );
}

type TableNewRowProps = Omit<TableRowProps, 'collection'> & {
  parent: Resource<DataBrowser.Table>;
  invalidateTable: () => void;
};

const resourceOpts = {
  newResource: true,
};

export function TableNewRow({
  index,
  columns,
  parent,
  invalidateTable,
}: TableNewRowProps): JSX.Element {
  const [subject] = useState<string>(() =>
    randomSubject(parent.subject, 'row'),
  );

  const [loading, setLoading] = useState(true);

  const resource = useResource(subject, resourceOpts);

  useEffect(() => {
    if (resource.subject === unknownSubject) {
      return;
    }

    resource
      .set(core.properties.parent, parent.subject)
      .then(() => resource.set(core.properties.isA, [parent.props.classtype]))
      .then(() => {
        setLoading(false);
      });
  }, [resource.subject]);

  if (loading) {
    return (
      <>
        {columns.map((column, i) => (
          <Loader key={column.subject} delay={i * 100} />
        ))}
      </>
    );
  }

  return (
    <>
      {columns.map((column, cIndex) => (
        <TableCellMemo
          key={column.subject}
          rowIndex={index}
          columnIndex={cIndex + 1}
          resource={resource}
          property={column}
          invalidateTable={invalidateTable}
        />
      ))}
    </>
  );
}

const pulse = keyframes`
  from {
    background-color: var(--from-color);
  }

  to {
    background-color: var(--to-color);
  }
`;

interface LoaderProps {
  delay: number;
}

const Loader = styled.div<LoaderProps>`
  width: 100%;
  --from-color: ${p => p.theme.colors.bg};
  --to-color: ${p => p.theme.colors.bg1};
  animation: 0.8s ${p => p.delay}ms ease-in-out infinite alternate ${pulse};
`;
