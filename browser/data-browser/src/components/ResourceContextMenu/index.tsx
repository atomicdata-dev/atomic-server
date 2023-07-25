import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { Client, useStore } from '@tomic/react';
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

export interface ResourceContextMenuProps {
  subject: string;
  // ID's of actions that are hidden
  hide?: string[];
  trigger?: DropdownTriggerRenderFunction;
  simple?: boolean;
  /** If it's the primary menu in the navbar. Used for triggering keyboard shortcut */
  isMainMenu?: boolean;
}

/** Dropdown menu that opens a bunch of actions for some resource */
function ResourceContextMenu({
  subject,
  hide,
  trigger,
  simple,
  isMainMenu,
}: ResourceContextMenuProps) {
  const store = useStore();
  const navigate = useNavigate();
  const location = useLocation();
  const { enableScope } = useQueryScopeHandler(subject);
  // Try to not have a useResource hook in here, as that will lead to many costly fetches when the user enters a new subject

  if (subject === undefined) {
    return null;
  }

  if (!Client.isValidSubject(subject)) {
    return null;
  }

  async function handleDestroy() {
    if (
      window.confirm(
        'Are you sure you want to permanently delete this resource?',
      )
    ) {
      const resource = store.getResourceLoading(subject);

      try {
        await resource.destroy(store);
        toast.success('Resource deleted!');
        navigate('/');
      } catch (error) {
        toast.error(error.message);
      }
    }
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
      onClick: handleDestroy,
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
    <DropdownMenu
      items={filteredItems}
      trigger={triggerComp}
      isMainMenu={isMainMenu}
    />
  );
}

export default ResourceContextMenu;
