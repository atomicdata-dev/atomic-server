import { useContext, type JSX } from 'react';
import { FaEllipsisVertical } from 'react-icons/fa6';
import { buildDefaultTrigger } from '@components/Dropdown/DefaultTrigger';
import type { DraggableAttributes } from '@dnd-kit/core';
import type { SyntheticListenerMap } from '@dnd-kit/core/dist/hooks/utilities';
import { TablePageContext } from './tablePageContext';
import { RowActionDialog } from './RowActionDialog';
import { ROW_ACTION_GENERATORS, type RowActionSpec } from './rowActions';
import { ColumnSpecHeading } from './ColumnSpecHeading';

const Trigger = buildDefaultTrigger(<FaEllipsisVertical />, 'Edit action');

/**
 * Heading of an action column: its label plus the menu that edits or removes it.
 * Nothing here sorts or filters — the column holds buttons, not values — but it
 * drags like any other, because where it sits is the view's column order.
 */
export function RowActionHeading({
  spec,
  readOnly,
  dragListeners,
  dragAttributes,
}: {
  spec: RowActionSpec;
  readOnly: boolean;
  dragListeners?: SyntheticListenerMap;
  dragAttributes?: DraggableAttributes;
}): JSX.Element {
  const { classProperties, updateRowAction, removeRowAction } =
    useContext(TablePageContext);

  return (
    <ColumnSpecHeading
      spec={spec}
      readOnly={readOnly}
      dragListeners={dragListeners}
      dragAttributes={dragAttributes}
      generatorTitle={ROW_ACTION_GENERATORS[spec.kind]?.title}
      Trigger={Trigger}
      removeTitle='Remove action'
      removeBody={
        <p>
          Remove the {spec.label} button from this view. Nothing already
          recorded by pressing it is affected — add it back any time.
        </p>
      }
      onRemove={() => removeRowAction(spec.id)}
      renderEditDialog={({ bindShow }) => (
        <RowActionDialog
          open
          bindShow={bindShow}
          classProperties={classProperties}
          editing={spec}
          onSave={updateRowAction}
        />
      )}
    />
  );
}
