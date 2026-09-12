import { useCallback, useEffect, useState } from 'react';
import { Client, useDrive } from '@tomic/react';
import { DIVIDER, DropdownMenu, isItem, DropdownItem } from '../Dropdown';
import { AutoOpenTrigger } from '../Dropdown/AutoOpenTrigger';
import { DropdownTriggerComponent } from '../Dropdown/DropdownTrigger';
import { buildDefaultTrigger } from '../Dropdown/DefaultTrigger';
import { FaEllipsisVertical } from 'react-icons/fa6';
import {
  ConfirmationDialog,
  ConfirmationDialogTheme,
} from '../ConfirmationDialog';
import { ResourceCodeUsageDialog } from '../../views/CodeUsage/ResourceCodeUsageDialog';
import { addIf } from '../../helpers/addIf';
import { resourceActions } from '../../actions/resourceActions';
import { useActionContext } from '../../actions/useActionContext';
import { runAction } from '../../actions/runAction';
import type { ActionDefinition } from '../../actions/types';
import { RunPluginDialog } from '@chunks/PluginRuns/RunPluginDialog';
import { usePluginClass } from '@chunks/PluginRuns/runScript';
import { useCustomContextItemsContext } from './CustomContextItemsContext';
import { CoverPickerDialog, EmojiPickerDialog } from '../ResourceDecorations';
import { ResourceInline } from '../../views/ResourceInline';
import { ResourceUsage } from '../ResourceUsage';

export {
  CustomContextItemsProvider,
  useCustomContextItems,
} from './CustomContextItemsContext';

export { ResourceContextMenuProvider } from './ResourceContextMenuProvider';
export { ResourceContextMenuHost } from './ResourceContextMenuHost';
export { useResourceContextMenu } from './ResourceContextMenuContext';

export { DIVIDER, type DropdownItem } from '../Dropdown';

/** Ids of the actions in the registry (`actions/resourceActions.tsx`). */
export const ContextMenuOptions = {
  View: 'view',
  Data: 'data',
  Edit: 'edit',
  Scope: 'scope',
  Share: 'share',
  Delete: 'delete',
  History: 'history',
  Import: 'import',
  UseInCode: 'useInCode',
  NewChild: 'newChild',
  Export: 'export',
  Open: 'open',
  AddToChat: 'addToChat',
  Favorite: 'favorite',
  Parent: 'parent',
  EditAsFork: 'editAsFork',
  MergeFork: 'mergeFork',
  OpenOriginal: 'openOriginal',
  SetEmoji: 'setEmoji',
  SetCover: 'setCover',
} as const;

export type ContextMenuOptionsUnion =
  (typeof ContextMenuOptions)[keyof typeof ContextMenuOptions];

export interface ResourceContextMenuProps {
  subject: string;
  // If given only these options will appear in the list.
  showOnly?: ContextMenuOptionsUnion[];
  trigger?: DropdownTriggerComponent;
  simple?: boolean;
  /** If it's the primary menu in the navbar. Used for triggering keyboard shortcut */
  isMainMenu?: boolean;
  bindActive?: (active: boolean) => void;
  /** Callback that is called after the resource was deleted */
  onAfterDelete?: () => void;
  title?: string;
  external?: boolean;
  /**
   * When set, opens the menu at this viewport point (a right-click context
   * menu) instead of anchoring to a trigger. Defaults the trigger to an
   * invisible auto-opening one unless an explicit `trigger` is given.
   */
  anchorPoint?: { x: number; y: number };
  /**
   * Render a filter input at the top so the user can type to narrow the
   * actions and run one with Enter. Defaults to on for the main menu
   * (navbar kebab / cmd+m) and for right-click menus, off for the small
   * embedded ones (`simple`, custom triggers).
   */
  searchable?: boolean;
}

/**
 * Dropdown menu that opens a bunch of actions for some resource. Items come
 * from the central action registry. The main menu (navbar kebab / cmd+m) and
 * the right-click menu on any resource (sidebar link, table cell, kanban
 * card) share the same searchable list: right-click, type, Enter.
 */
export function ResourceContextMenu({
  subject,
  showOnly,
  trigger,
  simple,
  isMainMenu,
  title,
  external,
  bindActive,
  onAfterDelete,
  anchorPoint,
  searchable,
}: ResourceContextMenuProps) {
  const [confirmingAction, setConfirmingAction] = useState<ActionDefinition>();
  const [showCodeUsageDialog, setShowCodeUsageDialog] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [shiftHeld, setShiftHeld] = useState(false);
  const openCodeUsageDialog = useCallback(
    () => setShowCodeUsageDialog(true),
    [],
  );
  // undefined = never opened (dialog not mounted), boolean = mounted.
  const [emojiPickerOpen, setEmojiPickerOpen] = useState<boolean>();
  const [coverPickerOpen, setCoverPickerOpen] = useState<boolean>();
  const [pluginRunOpen, setPluginRunOpen] = useState<boolean>();
  const openPluginRun = useCallback(() => setPluginRunOpen(true), []);
  const [currentDrive] = useDrive();
  const pluginClass = usePluginClass(currentDrive);
  const openEmojiPicker = useCallback(() => setEmojiPickerOpen(true), []);
  const openCoverPicker = useCallback(() => setCoverPickerOpen(true), []);
  const ctx = useActionContext(subject, {
    external,
    onAfterDelete,
    showCodeUsageDialog: openCodeUsageDialog,
    openEmojiPicker,
    openCoverPicker,
    openPluginRun,
    pluginClass,
  });
  const { items: customItems } = useCustomContextItemsContext();
  // Try to not have a useResource hook in here, as that will lead to many costly fetches when the user enters a new subject

  const handleBindActive = useCallback(
    (active: boolean) => {
      setMenuOpen(active);

      if (!active) {
        setShiftHeld(false);
      }

      bindActive?.(active);
    },
    [bindActive],
  );

  useEffect(() => {
    if (!menuOpen) {
      return;
    }

    const updateShiftFromEvent = (e: KeyboardEvent | MouseEvent) => {
      setShiftHeld(e.shiftKey);
    };

    document.addEventListener('keydown', updateShiftFromEvent);
    document.addEventListener('keyup', updateShiftFromEvent);
    document.addEventListener('mousemove', updateShiftFromEvent);

    return () => {
      document.removeEventListener('keydown', updateShiftFromEvent);
      document.removeEventListener('keyup', updateShiftFromEvent);
      document.removeEventListener('mousemove', updateShiftFromEvent);
    };
  }, [menuOpen]);

  if (subject === undefined) {
    return null;
  }

  if (!Client.isValidSubject(subject)) {
    return null;
  }

  const availableActions = resourceActions.filter(
    action =>
      (!simple || action.section !== 'view') &&
      (action.available?.(ctx) ?? true),
  );

  const items: DropdownItem[] = [];
  let previousSection: string | undefined;

  for (const action of availableActions) {
    if (previousSection !== undefined && action.section !== previousSection) {
      items.push(DIVIDER);
    }

    previousSection = action.section;

    items.push({
      id: action.id,
      label:
        shiftHeld && action.danger && action.dangerLabel
          ? action.dangerLabel(ctx)
          : action.label(ctx),
      helper: action.helper(ctx),
      icon: action.icon?.(ctx),
      shortcut: simple ? undefined : action.shortcut,
      disabled: action.disabled?.(ctx),
      keywords: action.keywords,
      searchOnly:
        typeof action.searchOnly === 'function'
          ? action.searchOnly(ctx)
          : action.searchOnly,
      onClick: () => {
        // Shift skips the confirmation dialog for danger actions.
        if (action.danger && action.confirmation && !shiftHeld) {
          setConfirmingAction(action);
        } else {
          runAction(action, ctx);
        }
      },
    });
  }

  // Add custom items from context (if any) before filtering
  const allItems = [
    ...items,
    ...addIf(subject === ctx.currentSubject, ...customItems),
  ];

  const filteredItems = showOnly
    ? allItems.filter(
        item =>
          !isItem(item) ||
          showOnly.includes(item.id as ContextMenuOptionsUnion),
      )
    : allItems;

  const triggerComp =
    trigger ??
    (anchorPoint
      ? AutoOpenTrigger
      : buildDefaultTrigger(
          <FaEllipsisVertical />,
          title ?? `Open ${ctx.resource.title} menu`,
        ));

  const confirmation = confirmingAction?.confirmation;

  return (
    <>
      <DropdownMenu
        items={filteredItems}
        Trigger={triggerComp}
        isMainMenu={isMainMenu}
        searchable={searchable ?? (!!isMainMenu || anchorPoint !== undefined)}
        bindActive={handleBindActive}
        anchorPoint={anchorPoint}
      />
      <ConfirmationDialog
        title={confirmation?.title(ctx) ?? ''}
        show={confirmingAction !== undefined}
        bindShow={show => {
          if (!show) {
            setConfirmingAction(undefined);
          }
        }}
        theme={ConfirmationDialogTheme.Alert}
        confirmLabel={confirmation?.confirmLabel(ctx)}
        onConfirm={() => {
          if (confirmingAction) runAction(confirmingAction, ctx);
        }}
      >
        {confirmingAction?.id === 'delete' ? (
          <>
            <p>
              <span>Are you sure you want to delete</span>{' '}
              <ResourceInline subject={ctx.subject} />
            </p>
            <ResourceUsage resource={ctx.resource} />
          </>
        ) : (
          confirmation?.body(ctx)
        )}
      </ConfirmationDialog>
      {/* Use the menu's own subject, not the current page's — a right-click can
       * target a resource other than the one being viewed. */}
      <ResourceCodeUsageDialog
        subject={subject}
        show={showCodeUsageDialog}
        bindShow={setShowCodeUsageDialog}
      />
      {/* Mounted lazily on first use — most menus never open these. */}
      {emojiPickerOpen !== undefined && (
        <EmojiPickerDialog
          resource={ctx.resource}
          show={emojiPickerOpen}
          onShowChange={setEmojiPickerOpen}
        />
      )}
      {coverPickerOpen !== undefined && (
        <CoverPickerDialog
          resource={ctx.resource}
          show={coverPickerOpen}
          onShowChange={setCoverPickerOpen}
        />
      )}
      {pluginRunOpen !== undefined && ctx.drive !== undefined && (
        <RunPluginDialog
          resource={ctx.resource}
          drive={ctx.drive}
          show={pluginRunOpen}
          onShowChange={setPluginRunOpen}
        />
      )}
    </>
  );
}
