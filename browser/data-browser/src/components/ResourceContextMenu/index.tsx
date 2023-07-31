import React, { useCallback } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { Client, properties, useResource, useStore } from '@tomic/react';
import {
  editURL,
  dataURL,
  constructOpenURL,
  historyURL,
  shareURL,
  importerURL,
} from '../../helpers/navigation';
import { DIVIDER, DropdownMenu, isItem, Item } from '../Dropdown';
import toast from 'react-hot-toast';
import { paths } from '../../routes/paths';
import { shortcuts } from '../HotKeyWrapper';
import { DropdownTriggerRenderFunction } from '../Dropdown/DropdownTrigger';
import { buildDefaultTrigger } from '../Dropdown/DefaultTrigger';
import {
  FaClock,
  FaDownload,
  FaEdit,
  FaEllipsisV,
  FaRedo,
  FaSearch,
  FaShareSquare,
  FaTrash,
} from 'react-icons/fa';
import { useQueryScopeHandler } from '../../hooks/useQueryScope';
import {
  ConfirmationDialog,
  ConfirmationDialogTheme,
} from '../ConfirmationDialog';
import { ResourceInline } from '../../views/ResourceInline';
import { ResourceUsage } from '../ResourceUsage';
import { useCurrentSubject } from '../../helpers/useCurrentSubject';

export interface ResourceContextMenuProps {
  subject: string;
  // ID's of actions that are hidden
  hide?: string[];
  trigger?: DropdownTriggerRenderFunction;
  simple?: boolean;
  /** If it's the primary menu in the navbar. Used for triggering keyboard shortcut */
  isMainMenu?: boolean;
  bindActive?: (active: boolean) => void;
}

/** Dropdown menu that opens a bunch of actions for some resource */
function ResourceContextMenu({
  subject,
  hide,
  trigger,
  simple,
  isMainMenu,
  bindActive,
}: ResourceContextMenuProps) {
  const store = useStore();
  const navigate = useNavigate();
  const location = useLocation();
  const resource = useResource(subject);
  const [showDeleteDialog, setShowDeleteDialog] = React.useState(false);
  const [currentSubject] = useCurrentSubject();

  const { enableScope } = useQueryScopeHandler(subject);
  // Try to not have a useResource hook in here, as that will lead to many costly fetches when the user enters a new subject

  const handleDestroy = useCallback(async () => {
    const parent = resource.get<string>(properties.parent);

    try {
      await resource.destroy(store);
      toast.success('Resource deleted!');

      if (currentSubject === subject) {
        navigate(parent ? constructOpenURL(parent) : '/');
      }
    } catch (error) {
      toast.error(error.message);
    }
  }, [resource, navigate, currentSubject]);

  if (subject === undefined) {
    return null;
  }

  if (!Client.isValidSubject(subject)) {
    return null;
  }

  const items: Item[] = [
    ...(simple
      ? []
      : [
          {
            disabled: location.pathname.startsWith(paths.show),
            id: 'view',
            label: 'normal view',
            helper: 'Open the regular, default View.',
            onClick: () => navigate(constructOpenURL(subject)),
          },
          {
            disabled: location.pathname.startsWith(paths.data),
            id: 'data',
            label: 'data view',
            helper: 'View the resource and its properties in the Data View.',
            shortcut: shortcuts.data,
            onClick: () => navigate(dataURL(subject)),
          },
          DIVIDER,
          {
            id: 'refresh',
            icon: <FaRedo />,
            label: 'refresh',
            helper:
              'Fetch the resouce again from the server, possibly see new changes.',
            onClick: () => store.fetchResourceFromServer(subject),
          },
        ]),
    {
      // disabled: !canWrite || location.pathname.startsWith(paths.edit),
      id: 'edit',
      label: 'edit',
      helper: 'Open the edit form.',
      icon: <FaEdit />,
      shortcut: simple ? '' : shortcuts.edit,
      onClick: () => navigate(editURL(subject)),
    },
    {
      id: 'scope',
      label: 'search in',
      helper: 'Scope search to resource',
      icon: <FaSearch />,
      onClick: enableScope,
    },
    {
      // disabled: !canWrite || history.location.pathname.startsWith(paths.edit),
      id: 'share',
      label: 'share',
      icon: <FaShareSquare />,
      helper: 'Open the share menu',
      onClick: () => navigate(shareURL(subject)),
    },
    {
      // disabled: !canWrite,
      id: 'delete',
      icon: <FaTrash />,
      label: 'delete',
      helper:
        'Fetch the resouce again from the server, possibly see new changes.',
      onClick: () => setShowDeleteDialog(true),
    },
    {
      id: 'history',
      icon: <FaClock />,
      label: 'history',
      helper: 'Show the history of this resource',
      onClick: () => navigate(historyURL(subject)),
    },
    {
      id: 'import',
      icon: <FaDownload />,
      label: 'import',
      helper: 'Import Atomic Data to this resource',
      onClick: () => navigate(importerURL(subject)),
    },
  ];

  const filteredItems = hide
    ? items.filter(item => !isItem(item) || !hide.includes(item.id))
    : items;

  const triggerComp = trigger ?? buildDefaultTrigger(<FaEllipsisV />);

  return (
    <>
      <DropdownMenu
        items={filteredItems}
        trigger={triggerComp}
        isMainMenu={isMainMenu}
        bindActive={bindActive}
      />
      <ConfirmationDialog
        title={`Delete resource`}
        show={showDeleteDialog}
        bindShow={setShowDeleteDialog}
        theme={ConfirmationDialogTheme.Alert}
        confirmLabel={'Delete'}
        onConfirm={handleDestroy}
      >
        <>
          <p>
            Are you sure you want to delete <ResourceInline subject={subject} />
          </p>
          <ResourceUsage resource={resource} />
        </>
      </ConfirmationDialog>
    </>
  );
}

export default ResourceContextMenu;
