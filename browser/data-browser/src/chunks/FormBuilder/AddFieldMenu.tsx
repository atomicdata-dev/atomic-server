import { Resource } from '@tomic/react';
import { useNavigate } from '@tanstack/react-router';
import { constructOpenURL } from '@helpers/navigation';
import { compatibleFieldTypes, columnLabel } from './tableColumns';
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
  onAdd: (type: AddableFieldType, property?: Resource) => void;
  columns?: Resource[];
  tableSubject?: string;
}

export function AddFieldMenu({
  onAdd,
  columns,
  tableSubject,
}: AddFieldMenuProps): JSX.Element {
  const navigate = useNavigate();
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

    if (columns) {
      const columnItems: DropdownItem[] = columns.map(property => {
        const type = compatibleFieldTypes(property)[0];
        const Icon = type && FIELD_TYPE_META[type].icon;

        return {
          id: property.subject,
          label: columnLabel(property),
          disabled: !type,
          helper: type ? undefined : 'Not supported in forms',
          icon: Icon ? <Icon /> : undefined,
          onClick: () => type && onAdd(type, property),
        };
      });
      if (!columns.length)
        columnItems.push({
          id: 'all-columns',
          label:
            'All columns are on this form. Add a column to the table to ask something new.',
          disabled: true,
          onClick: () => {},
        });
      columnItems.push({
        id: 'open-table',
        label: 'Add a column to the table',
        onClick: () =>
          tableSubject && navigate({ to: constructOpenURL(tableSubject) }),
      });

      return [...columnItems, DIVIDER, ...FORM_LAYOUT_TYPES.map(toItem)];
    }

    // A divider between each group of related question types, and one more
    // before the layout blocks — the flat list is too long to scan otherwise.
    const groups = [...FIELD_TYPE_GROUPS, FORM_LAYOUT_TYPES];

    return groups.flatMap((group, index) => [
      ...(index === 0 ? [] : [DIVIDER]),
      ...group.map(toItem),
    ]);
  }, [onAdd, columns, tableSubject, navigate]);

  return <DropdownMenu Trigger={AddFieldTrigger} items={items} />;
}
