import { JSONValue, useResource } from '@tomic/react';
import { CellContainer, DisplayCellProps, EditCellProps } from './Type';
import { getCategoryFromResource } from '../PropertyForm/categories';
import { SelectCell } from './SelectCell';
import { MultiRelationCell } from './MultiRelationCell';

function ResourceArrayCellEdit(props: EditCellProps<JSONValue>): JSX.Element {
  const propResource = useResource(props.property);

  if (getCategoryFromResource(propResource) === 'select') {
    return <SelectCell.Edit {...props} />;
  } else {
    return <MultiRelationCell.Edit {...props} />;
  }
}

function ResourceArrayCellDisplay(
  props: DisplayCellProps<JSONValue>,
): JSX.Element {
  const property = useResource(props.property);

  if (getCategoryFromResource(property) === 'select') {
    return <SelectCell.Display {...props} />;
  } else {
    return <MultiRelationCell.Display {...props} />;
  }
}

export const ResourceArrayCell: CellContainer<JSONValue> = {
  Edit: ResourceArrayCellEdit,
  Display: ResourceArrayCellDisplay,
};
