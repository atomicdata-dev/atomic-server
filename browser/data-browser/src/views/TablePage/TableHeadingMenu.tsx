import {
  Resource,
  properties,
  useCanWrite,
  useResource,
  useStore,
  useString,
  core,
} from '@tomic/react';
import { useCallback, useContext, useMemo, useState } from 'react';
import { DropdownMenu, Item } from '../../components/Dropdown';
import { buildDefaultTrigger } from '../../components/Dropdown/DefaultTrigger';
import { FaEdit, FaEllipsisV, FaEye, FaTimes, FaTrash } from 'react-icons/fa';
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
  const store = useStore();
  const canWrite = useCanWrite(resource);
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const { tableClassSubject } = useContext(TablePageContext);
  const tableClassResource = useResource(tableClassSubject);
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
      recommends.filter(r => r !== resource.getSubject()),
      store,
    );

    await tableClassResource.set(
      core.properties.requires,
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
      {
        id: 'view',
        label: 'View',
        onClick: () => {
          navigate(constructOpenURL(resource.getSubject()));
        },
        icon: <FaEye />,
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
