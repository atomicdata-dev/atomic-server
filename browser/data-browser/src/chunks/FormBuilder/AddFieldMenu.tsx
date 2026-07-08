import { useMemo, type JSX } from 'react';
import { FaPlus } from 'react-icons/fa6';
import { DIVIDER, DropdownMenu, DropdownItem } from '@components/Dropdown';
import { buildDefaultTrigger } from '@components/Dropdown/DefaultTrigger';
import {
  FORM_FIELD_TYPES,
  FORM_LAYOUT_TYPES,
  FIELD_TYPE_META,
  type AddableFieldType,
} from './fieldTypes';

const AddFieldTrigger = buildDefaultTrigger(<FaPlus />, 'Add field');

interface AddFieldMenuProps {
  onAdd: (type: AddableFieldType) => void;
}

export function AddFieldMenu({ onAdd }: AddFieldMenuProps): JSX.Element {
  const items = useMemo((): DropdownItem[] => {
    const fieldItems = FORM_FIELD_TYPES.map(type => ({
      id: type,
      label: FIELD_TYPE_META[type].label,
      icon: (() => {
        const Icon = FIELD_TYPE_META[type].icon;

        return <Icon />;
      })(),
      onClick: () => onAdd(type),
    }));

    const layoutItems = FORM_LAYOUT_TYPES.map(type => ({
      id: type,
      label: FIELD_TYPE_META[type].label,
      icon: (() => {
        const Icon = FIELD_TYPE_META[type].icon;

        return <Icon />;
      })(),
      onClick: () => onAdd(type),
    }));

    return [...fieldItems, DIVIDER, ...layoutItems];
  }, [onAdd]);

  return <DropdownMenu Trigger={AddFieldTrigger} items={items} />;
}
