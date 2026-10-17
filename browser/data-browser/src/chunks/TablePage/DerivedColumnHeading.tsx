import { useContext, type JSX } from 'react';
import { FaEllipsisVertical } from 'react-icons/fa6';
import { buildDefaultTrigger } from '@components/Dropdown/DefaultTrigger';
import type { DraggableAttributes } from '@dnd-kit/core';
import type { SyntheticListenerMap } from '@dnd-kit/core/dist/hooks/utilities';
import { TablePageContext } from './tablePageContext';
import { DerivedColumnDialog } from './DerivedColumnDialog';
import {
  DERIVED_COLUMN_GENERATORS,
  type DerivedColumnSpec,
} from './derivedColumns';
import { ColumnSpecHeading } from './ColumnSpecHeading';

const Trigger = buildDefaultTrigger(
  <FaEllipsisVertical />,
  'Edit computed column',
);

/**
 * Heading of a computed column: its label plus the menu that edits or removes
 * it. There is no property behind it, so nothing here sorts or filters —
 * what it offers is the configuration that produced the column.
 */
export function DerivedColumnHeading({
  spec,
  readOnly,
  dragListeners,
  dragAttributes,
}: {
  spec: DerivedColumnSpec;
  readOnly: boolean;
  dragListeners?: SyntheticListenerMap;
  dragAttributes?: DraggableAttributes;
}): JSX.Element {
  const { classProperties, updateDerivedColumn, removeDerivedColumn } =
    useContext(TablePageContext);

  return (
    <ColumnSpecHeading
      spec={spec}
      readOnly={readOnly}
      dragListeners={dragListeners}
      dragAttributes={dragAttributes}
      generatorTitle={DERIVED_COLUMN_GENERATORS[spec.kind]?.title}
      Trigger={Trigger}
      removeTitle='Remove computed column'
      removeBody={
        <p>
          Remove the {spec.label} column from this view. It is computed, so no
          data is deleted — add it back any time.
        </p>
      }
      onRemove={() => removeDerivedColumn(spec.id)}
      renderEditDialog={({ bindShow }) => (
        <DerivedColumnDialog
          open
          bindShow={bindShow}
          classProperties={classProperties}
          editing={spec}
          onSave={updateDerivedColumn}
        />
      )}
    />
  );
}
