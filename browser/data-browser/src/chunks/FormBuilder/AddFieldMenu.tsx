import { useMemo, type JSX } from 'react';
import { FaPlus } from 'react-icons/fa6';
import { DIVIDER, DropdownMenu, DropdownItem } from '@components/Dropdown';
import { buildDefaultTrigger } from '@components/Dropdown/DefaultTrigger';
import {
  FIELD_TYPE_GROUPS,
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
    const toItem = (type: AddableFieldType) => ({
      id: type,
      label: FIELD_TYPE_META[type].label,
      icon: (() => {
        const Icon = FIELD_TYPE_META[type].icon;

        return <Icon />;
      })(),
      onClick: () => onAdd(type),
    });

    // A divider between each group of related question types, and one more
    // before the layout blocks — the flat list is too long to scan otherwise.
    const groups = [...FIELD_TYPE_GROUPS, FORM_LAYOUT_TYPES];

    return groups.flatMap((group, index) => [
      ...(index === 0 ? [] : [DIVIDER]),
      ...group.map(toItem),
    ]);
  }, [onAdd]);

  return <DropdownMenu Trigger={AddFieldTrigger} items={items} />;
}
