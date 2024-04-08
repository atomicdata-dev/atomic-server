import {
  Resource,
  properties,
  useCanWrite,
  useResource,
  useString,
  core,
} from '@tomic/react';
import { useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { DropdownMenu, Item } from '../../components/Dropdown';
import { buildDefaultTrigger } from '../../components/Dropdown/DefaultTrigger';
import { FaEdit, FaEllipsisV, FaEye, FaTimes } from 'react-icons/fa';
import { styled } from 'styled-components';
import { EditPropertyDialog } from './PropertyForm/EditPropertyDialog';
import { TablePageContext } from './tablePageContext';
import {
  ConfirmationDialog,
  ConfirmationDialogTheme,
} from '../../components/ConfirmationDialog';
import { ResourceInline } from '../ResourceInline';
import { ResourceUsage } from '../../components/ResourceUsage';
import { useNavigate } from 'react-router';
import { constructOpenURL } from '../../helpers/navigation';
import { Checkbox, CheckboxLabel } from '../../components/forms/Checkbox';
import { Column } from '../../components/Row';

interface TableHeadingMenuProps {
  resource: Resource;
}

const Trigger = buildDefaultTrigger(<FaEllipsisV />, 'Edit column');

const useIsExternalProperty = (property: Resource) => {
  const { tableClassSubject } = useContext(TablePageContext);
  const [parent] = useString(property, properties.parent);

  return parent !== tableClassSubject;
};

export function TableHeadingMenu({
  resource,
}: TableHeadingMenuProps): JSX.Element {
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [fullDelete, setFullDelete] = useState(false);

  const { tableClassSubject } = useContext(TablePageContext);
  const tableClassResource = useResource(tableClassSubject);
  const [canWriteClass] = useCanWrite(tableClassResource);
  const [canWriteProperty] = useCanWrite(resource);
  const navigate = useNavigate();

  const isExternalProperty = useIsExternalProperty(resource);

  const removeProperty = useCallback(async () => {
    const recommends = tableClassResource.getArray(
      core.properties.recommends,
    ) as string[];
    const requires = tableClassResource.getArray(
      core.properties.requires,
    ) as string[];

    await tableClassResource.set(
      core.properties.recommends,
      recommends.filter(r => r !== resource.subject),
    );

    await tableClassResource.set(
      core.properties.requires,
      requires.filter(r => r !== resource.subject),
    );

    await tableClassResource.save();
  }, [tableClassResource, resource]);

  const deleteProperty = useCallback(async () => {
    await removeProperty();

    resource.destroy();
  }, [removeProperty]);

  const onConfirm = useCallback(() => {
    if (isExternalProperty) {
      removeProperty();
    } else {
      deleteProperty();
    }
  }, [deleteProperty, removeProperty, isExternalProperty]);

  const items = useMemo(
    (): Item[] => [
      {
        id: 'view',
        label: 'View',
        onClick: () => {
          navigate(constructOpenURL(resource.subject));
        },
        icon: <FaEye />,
      },
      {
        id: 'edit',
        label: 'Edit',
        onClick: () => setShowEditDialog(true),
        icon: <FaEdit />,
        disabled: !canWriteProperty,
      },
      {
        id: 'remove',
        label: 'Remove',
        onClick: () => setShowDeleteDialog(true),
        icon: <FaTimes />,
        disabled: !canWriteClass,
      },
    ],
    [canWriteClass, canWriteProperty, navigate, resource],
  );

  // Reset fullDelete when dialog is closed
  useEffect(() => {
    if (!showDeleteDialog) {
      setFullDelete(false);
    }
  }, [showDeleteDialog]);

  return (
    <Wrapper>
      <DropdownMenu trigger={Trigger} items={items} />
      <EditPropertyDialog
        resource={resource}
        showDialog={showEditDialog}
        bindShow={setShowEditDialog}
      />
      <ConfirmationDialog
        title={fullDelete ? 'Delete property' : 'Remove column'}
        confirmLabel={fullDelete ? 'Delete' : 'Remove'}
        show={showDeleteDialog}
        bindShow={setShowDeleteDialog}
        theme={ConfirmationDialogTheme.Alert}
        onConfirm={onConfirm}
      >
        <Column>
          <p>
            Remove <ResourceInline subject={resource.subject} /> from{' '}
            <ResourceInline subject={tableClassSubject} />
          </p>
          <ResourceUsage resource={resource} />
          <CheckboxLabel>
            <Checkbox checked={fullDelete} onChange={setFullDelete} />
            Delete property and its children
          </CheckboxLabel>
        </Column>
      </ConfirmationDialog>
    </Wrapper>
  );
}

const Wrapper = styled.div`
  margin-left: auto;

  & > button {
    color: ${p => p.theme.colors.textLight};
  }
`;
