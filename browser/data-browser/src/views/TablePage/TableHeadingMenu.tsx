import {
  Resource,
  properties,
  useCanWrite,
  useStore,
  useString,
} from '@tomic/react';
import React, { useCallback, useContext, useMemo, useState } from 'react';
import { DropdownMenu, Item } from '../../components/Dropdown';
import { buildDefaultTrigger } from '../../components/Dropdown/DefaultTrigger';
import { FaEdit, FaEllipsisV, FaTimes, FaTrash } from 'react-icons/fa';
import styled from 'styled-components';
import { EditPropertyDialog } from './PropertyForm/EditPropertyDialog';
import { TablePageContext } from './tablePageContext';
import {
  ConfirmationDialog,
  ConfirmationDialogTheme,
} from '../../components/ConfirmationDialog';
import { ResourceInline } from '../ResourceInline';
import { ResourceUsage } from '../../components/ResourceUsage';

interface TableHeadingMenuProps {
  resource: Resource;
}

const Trigger = buildDefaultTrigger(<FaEllipsisV />, 'Edit column');

const useIsExternalProperty = (property: Resource) => {
  const { tableClassResource } = useContext(TablePageContext);
  const [parent] = useString(property, properties.parent);

  return parent !== tableClassResource.getSubject();
};

export function TableHeadingMenu({
  resource,
}: TableHeadingMenuProps): JSX.Element {
  const store = useStore();
  const canWrite = useCanWrite(resource);
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const { tableClassResource } = useContext(TablePageContext);

  const isExternalProperty = useIsExternalProperty(resource);

  const removeProperty = useCallback(async () => {
    const recommends =
      tableClassResource.get<string[]>(properties.recommends) ?? [];
    const requires =
      tableClassResource.get<string[]>(properties.requires) ?? [];

    await tableClassResource.set(
      properties.recommends,
      recommends.filter(r => r !== resource.getSubject()),
      store,
    );

    await tableClassResource.set(
      properties.requires,
      requires.filter(r => r !== resource.getSubject()),
      store,
    );

    await tableClassResource.save(store);
  }, [store, tableClassResource, resource]);

  const deleteProperty = useCallback(async () => {
    await removeProperty();

    resource.destroy(store);
  }, [removeProperty, store]);

  const onConfirm = useCallback(() => {
    if (isExternalProperty) {
      removeProperty();
    } else {
      deleteProperty();
    }
  }, [deleteProperty, removeProperty, isExternalProperty]);

  const items = useMemo((): Item[] => {
    const initialItems = [
      {
        id: 'edit',
        label: 'Edit',
        onClick: () => setShowEditDialog(true),
        icon: <FaEdit />,
        disabled: !canWrite || isExternalProperty,
      },
    ];

    if (isExternalProperty) {
      initialItems.push({
        id: 'remove',
        label: 'Remove',
        onClick: () => setShowDeleteDialog(true),
        icon: <FaTimes />,
        disabled: !canWrite,
      });
    } else {
      initialItems.push({
        id: 'delete',
        label: 'Delete',
        onClick: () => setShowDeleteDialog(true),
        icon: <FaTrash />,
        disabled: !canWrite,
      });
    }

    return initialItems;
  }, []);

  return (
    <Wrapper>
      <DropdownMenu trigger={Trigger} items={items} />
      <EditPropertyDialog
        resource={resource}
        showDialog={showEditDialog}
        bindShow={setShowEditDialog}
      />
      <ConfirmationDialog
        title={isExternalProperty ? 'Remove column' : 'Delete column'}
        confirmLabel={isExternalProperty ? 'Remove' : 'Delete'}
        show={showDeleteDialog}
        bindShow={setShowDeleteDialog}
        theme={ConfirmationDialogTheme.Alert}
        onConfirm={onConfirm}
      >
        {isExternalProperty ? (
          <p>
            Remove <ResourceInline subject={resource.getSubject()} /> from this
            table
          </p>
        ) : (
          <>
            <p>
              Are you sure you want to delete this column?
              <br />
              This will delete the{' '}
              <ResourceInline subject={resource.getSubject()} /> property and
              its children.
            </p>
            <ResourceUsage resource={resource} />
          </>
        )}
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
