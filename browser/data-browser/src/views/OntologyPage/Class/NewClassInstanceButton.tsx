import { Core, Resource } from '@tomic/react';
import { FaPlus, FaAtom, FaTable } from 'react-icons/fa';
import { DropdownItem, DropdownMenu } from '../../../components/Dropdown';
import { buildDefaultTrigger } from '../../../components/Dropdown/DefaultTrigger';
import { useState } from 'react';
import { ParentPickerDialog } from '../../../components/ParentPicker/ParentPickerDialog';
import { useNewResourceUI } from '../../../components/forms/NewForm/useNewResourceUI';
import { NewTableDialog } from '../../../components/forms/NewForm/CustomCreateActions/CustomForms/NewTableDialog';
import { styled } from 'styled-components';

interface NewClassInstanceButtonProps {
  resource: Resource<Core.Class>;
}

enum InstanceType {
  SingleInstance,
  Table,
}

export function NewClassInstanceButton({
  resource,
}: NewClassInstanceButtonProps): React.JSX.Element {
  const showNewResourceUI = useNewResourceUI();

  const [showParentPicker, setShowParentPicker] = useState(false);
  const [showTableDialogWithParent, setShowTableDialogWithParent] =
    useState<string>();
  const [instanceType, setInstanceType] = useState<InstanceType>();

  const handleSelect = (parent: string) => {
    if (instanceType === InstanceType.SingleInstance) {
      showNewResourceUI(resource.subject, parent);
    } else {
      setShowTableDialogWithParent(parent);
    }

    setInstanceType(undefined);
  };

  const onTableDialogClose = () => {
    setShowTableDialogWithParent(undefined);
  };

  const trigger = buildDefaultTrigger(
    <PlusIcon />,
    `New instance of ${resource.title}`,
  );

  const newInstanceItems: DropdownItem[] = [
    {
      id: 'new-instance',
      label: 'Single instance',
      icon: <FaAtom />,
      onClick: () => {
        setInstanceType(InstanceType.SingleInstance);
        setShowParentPicker(true);
      },
    },
    {
      id: 'new-table',
      label: 'Table',
      icon: <FaTable />,
      onClick: () => {
        setInstanceType(InstanceType.Table);
        setShowParentPicker(true);
      },
    },
  ];

  return (
    <>
      <DropdownMenu items={newInstanceItems} trigger={trigger} />
      <ParentPickerDialog
        open={showParentPicker}
        onOpenChange={setShowParentPicker}
        onSelect={handleSelect}
      />
      {showTableDialogWithParent && (
        <NewTableDialog
          parent={showTableDialogWithParent}
          initialExistingClass={resource.subject}
          onClose={onTableDialogClose}
        />
      )}
    </>
  );
}

const PlusIcon = styled(FaPlus)`
  color: ${p => p.theme.colors.textLight};
`;
