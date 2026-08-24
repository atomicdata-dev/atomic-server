import {
  dataBrowser,
  Property,
  useResource,
  useString,
  useTitle,
} from '@tomic/react';
import { useContext, useMemo, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import {
  FaCheck,
  FaCopy,
  FaFilter,
  FaPencil,
  FaPlus,
  FaTableColumns,
  FaWindowMaximize,
  FaTrash,
} from 'react-icons/fa6';
import { DIVIDER, DropdownMenu, DropdownItem } from '@components/Dropdown';
import { buildDefaultTrigger } from '@components/Dropdown/DefaultTrigger';
import { AutoOpenTrigger } from '@components/Dropdown/AutoOpenTrigger';
import {
  ConfirmationDialog,
  ConfirmationDialogTheme,
} from '@components/ConfirmationDialog';
import { InputStyled } from '@components/forms/InputStyles';
import { useStore } from '@tomic/react';
import { TablePageContext } from './tablePageContext';
import {
  appsForClass,
  useDriveApps,
  type DriveApp,
} from '@chunks/AppPage/useDriveApps';
import type { DerivedColumnSpec } from './derivedColumns';
import { derivedFilterKey, filterKey } from './tableFiltering';
import { usePropertyTitles } from './helpers/usePropertyTitles';
import {
  normalizeViewKind,
  VIEW_KINDS,
  VIEW_KIND_LABELS,
  VIEW_KIND_ICONS,
  ViewKind,
} from './tableViewKinds';
import { QuickAddDialog } from './QuickAddDialog';
import type { QuickAddSpec } from './quickAdd';

interface TableViewTabsProps {
  /** The class of this table's rows, which decides what apps can show it. */
  rowClass: string;
  views: string[];
  activeView: string | undefined;
  setActiveView: (subject: string) => void;
  createView: (kind?: ViewKind | string, label?: string) => void;
  setViewKind: (subject: string, kind: ViewKind | string) => void;
  duplicateView: (subject: string) => void;
  deleteView: (subject: string) => void;
  viewName: string;
  renameView: (name: string) => void;
  allColumns: Property[];
  columns: Property[];
  /** The view's computed columns — filterable, like the stored ones. */
  derivedColumns: DerivedColumnSpec[];
  showColumn: (subject: string) => void;
  hideColumn: (subject: string) => void;
  /**
   * Properties the active view kind uses structurally (a timer's start/end, a
   * kanban's group-by). Toggling them would be a lie — the view renders them
   * either way — so they're shown as locked instead.
   */
  lockedColumns: ReadonlySet<string>;
  /** Why those are locked, e.g. "Always used by the timer view". */
  lockedReason: string;
  canWrite: boolean;
  /** The active view's create button, if it has one. */
  quickAdd: QuickAddSpec | undefined;
  /** Persist the active view's create button (undefined removes it). */
  setQuickAdd: (spec: QuickAddSpec | undefined) => void;
}

/**
 * The view-settings row (Notion-style): one tab per saved View on the left
 * with a `+` to add one, and a column-visibility menu on the right. The active
 * tab is renamed inline by double-clicking it.
 */
export function TableViewTabs({
  rowClass,
  views,
  activeView,
  setActiveView,
  createView,
  setViewKind,
  duplicateView,
  deleteView,
  viewName,
  renameView,
  allColumns,
  columns,
  derivedColumns,
  showColumn,
  hideColumn,
  lockedColumns,
  lockedReason,
  canWrite,
  quickAdd,
  setQuickAdd,
}: TableViewTabsProps): JSX.Element {
  // A table with no saved views yet still shows one implicit "Default View" tab.
  const tabs = views.length > 0 ? views : [undefined];
  const apps = appsForClass(useDriveApps(useStore().getDrive()), rowClass);

  return (
    <Bar>
      <Tabs role='tablist'>
        {tabs.map((subject, i) => (
          <ViewTab
            key={subject ?? `implicit-${i}`}
            subject={subject}
            active={subject === activeView || (!activeView && i === 0)}
            fallbackName={subject ? undefined : viewName}
            canWrite={canWrite}
            onSelect={() => subject && setActiveView(subject)}
            onRename={renameView}
            setViewKind={setViewKind}
            apps={apps}
            duplicateView={duplicateView}
            deleteView={deleteView}
            classProperties={allColumns}
            quickAdd={quickAdd}
            setQuickAdd={setQuickAdd}
          />
        ))}
        {canWrite && <AddViewMenu createView={createView} apps={apps} />}
      </Tabs>
      <Actions>
        <FilterMenu columns={columns} derivedColumns={derivedColumns} />
        <ColumnsMenu
          allColumns={allColumns}
          columns={columns}
          showColumn={showColumn}
          hideColumn={hideColumn}
          lockedColumns={lockedColumns}
          lockedReason={lockedReason}
          canWrite={canWrite}
        />
      </Actions>
    </Bar>
  );
}

const AddViewTrigger = buildDefaultTrigger(<FaPlus />, 'Add view');

/** The `+` tab: a dropdown to add a new view of a chosen kind (Table/Kanban). */
function AddViewMenu({
  createView,
  apps,
}: {
  createView: (kind?: ViewKind | string, label?: string) => void;
  apps: DriveApp[];
}): JSX.Element {
  const items = useMemo(
    (): DropdownItem[] => [
      ...VIEW_KINDS.map(kind => {
        const Icon = VIEW_KIND_ICONS[kind];

        return {
          id: kind,
          label: VIEW_KIND_LABELS[kind],
          icon: <Icon />,
          onClick: () => createView(kind),
        };
      }),
      // An app is another kind of view, added the same way. It arrives as a
      // new tab: the table's own views stay exactly as they were.
      ...apps.map(app => ({
        id: app.subject,
        label: app.name,
        icon: <FaWindowMaximize />,
        onClick: () => createView(app.subject, app.name),
      })),
    ],
    [createView, apps],
  );

  return <DropdownMenu Trigger={AddViewTrigger} items={items} />;
}

const FilterTrigger = buildDefaultTrigger(<FaFilter />, 'Filter');

/** Dropdown that adds a filter for one of the table's columns. */
function FilterMenu({
  columns,
  derivedColumns,
}: {
  columns: Property[];
  derivedColumns: DerivedColumnSpec[];
}): JSX.Element {
  const { filters, addFilter } = useContext(TablePageContext);
  const titles = usePropertyTitles(columns);

  const items = useMemo((): DropdownItem[] => {
    const taken = new Set(filters.map(filterKey));
    const available = columns.filter(c => !taken.has(c.subject));
    // A computed column narrows rows too — the store evaluates it per row, so
    // "logged more than an hour" or "due" is a filter like any other.
    const availableDerived = derivedColumns.filter(
      spec => !taken.has(derivedFilterKey(spec.id)),
    );

    if (available.length === 0 && availableDerived.length === 0) {
      return [];
    }

    return [
      {
        id: 'filter-header',
        label: 'Filter rows by a column',
        header: true,
        onClick: () => undefined,
      },
      ...available.map(c => ({
        id: c.subject,
        label: titles.get(c.subject) ?? c.shortname,
        onClick: () => addFilter(c.subject),
      })),
      ...availableDerived.map(spec => ({
        id: derivedFilterKey(spec.id),
        label: spec.label,
        onClick: () => addFilter(derivedFilterKey(spec.id)),
      })),
    ];
  }, [columns, derivedColumns, filters, addFilter, titles]);

  // `DropdownMenu` with an empty item list recurses forever in its
  // index-finder, so render a disabled button when there's nothing to filter
  // (columns still loading, or every column already filtered).
  if (items.length === 0) {
    return (
      <IconBtn disabled title='Filter' type='button'>
        <FaFilter />
      </IconBtn>
    );
  }

  return <DropdownMenu Trigger={FilterTrigger} items={items} />;
}

function ViewTab({
  subject,
  active,
  fallbackName,
  canWrite,
  onSelect,
  onRename,
  setViewKind,
  apps,
  duplicateView,
  deleteView,
  classProperties,
  quickAdd,
  setQuickAdd,
}: {
  subject: string | undefined;
  active: boolean;
  fallbackName?: string;
  canWrite: boolean;
  onSelect: () => void;
  onRename: (name: string) => void;
  setViewKind: (subject: string, kind: ViewKind | string) => void;
  /** Resolved once by the tab bar rather than once per tab. */
  apps: DriveApp[];
  duplicateView: (subject: string) => void;
  deleteView: (subject: string) => void;
  classProperties: Property[];
  quickAdd: QuickAddSpec | undefined;
  setQuickAdd: (spec: QuickAddSpec | undefined) => void;
}): JSX.Element {
  const resource = useResource(subject ?? 'unknown-subject');
  const [title] = useTitle(resource);
  const [storedKind] = useString(resource, dataBrowser.properties.viewKind);
  const currentKind = normalizeViewKind(storedKind);
  const name = subject ? title || 'Untitled view' : (fallbackName ?? 'View');
  const ViewKindIcon = VIEW_KIND_ICONS[currentKind];

  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(name);
  // The cursor point of an open context menu (right-click, or clicking the
  // already-active tab). `undefined` = closed.
  const [menuPoint, setMenuPoint] = useState<{ x: number; y: number }>();
  const [showDelete, setShowDelete] = useState(false);
  const [showQuickAdd, setShowQuickAdd] = useState(false);

  const startRename = () => {
    setDraft(name);
    setEditing(true);
  };

  // The menu is only meaningful for saved views (real subject) with write access.
  const hasMenu = canWrite && !!subject;

  const openMenuAt = (e: React.MouseEvent) => {
    if (!hasMenu) {
      return;
    }

    e.preventDefault();
    setMenuPoint({ x: e.clientX, y: e.clientY });
  };

  const menuItems: DropdownItem[] = subject
    ? [
        {
          id: 'rename',
          label: 'Rename',
          icon: <FaPencil />,
          onClick: startRename,
        },
        {
          id: 'duplicate',
          label: 'Duplicate',
          icon: <FaCopy />,
          onClick: () => duplicateView(subject),
        },
        {
          id: 'delete',
          label: 'Delete',
          icon: <FaTrash />,
          onClick: () => setShowDelete(true),
        },
        // Only on the active tab: `setQuickAdd` writes to the active view, so
        // offering it elsewhere would edit a view the user is not looking at.
        ...(active
          ? [
              DIVIDER,
              {
                id: 'quick-add',
                label: quickAdd ? 'Edit the add button' : 'Add a create button',
                helper:
                  'A button above the rows that creates one — "Log a feed", "Add item".',
                icon: <FaPlus />,
                onClick: () => setShowQuickAdd(true),
              },
            ]
          : []),
        DIVIDER,
        {
          id: 'view-type',
          label: 'View type',
          header: true,
          onClick: () => undefined,
        },
        ...VIEW_KINDS.map(kind => ({
          id: `kind-${kind}`,
          label: VIEW_KIND_LABELS[kind],
          icon: kind === currentKind ? <FaCheck /> : undefined,
          onClick: () => setViewKind(subject, kind),
        })),
        // An app is another way of looking at these rows, chosen the same way
        // as a built-in kind. It is set on this view only — the table's own
        // Table tab is untouched, and no app becomes the default.
        ...apps.map(app => ({
          id: `kind-${app.subject}`,
          label: app.name,
          icon: app.subject === storedKind ? <FaCheck /> : undefined,
          onClick: () => setViewKind(subject, app.subject),
        })),
      ]
    : [];

  if (editing) {
    return (
      <TabInput
        autoFocus
        value={draft}
        onChange={e => setDraft(e.target.value)}
        onBlur={() => {
          const trimmed = draft.trim();

          if (trimmed && trimmed !== name) {
            onRename(trimmed);
          }

          setEditing(false);
        }}
        onKeyDown={e => {
          if (e.key === 'Enter') {
            (e.target as HTMLInputElement).blur();
          } else if (e.key === 'Escape') {
            setDraft(name);
            setEditing(false);
          }
        }}
      />
    );
  }

  return (
    <>
      <Tab
        role='tab'
        aria-selected={active}
        $active={active}
        onClick={e => {
          // Clicking the already-active tab opens its menu; otherwise select.
          if (active && hasMenu) {
            openMenuAt(e);
          } else {
            onSelect();
          }
        }}
        onContextMenu={openMenuAt}
        type='button'
      >
        <ViewKindIcon />
        {name}
      </Tab>
      {menuPoint && (
        <DropdownMenu
          items={menuItems}
          Trigger={AutoOpenTrigger}
          anchorPoint={menuPoint}
          bindActive={a => !a && setMenuPoint(undefined)}
        />
      )}
      {showQuickAdd && (
        <QuickAddDialog
          open
          bindShow={setShowQuickAdd}
          classProperties={classProperties}
          editing={quickAdd}
          onSave={setQuickAdd}
        />
      )}
      {subject && (
        <ConfirmationDialog
          title='Delete view'
          show={showDelete}
          bindShow={setShowDelete}
          theme={ConfirmationDialogTheme.Alert}
          confirmLabel='Delete'
          onConfirm={() => deleteView(subject)}
        >
          <p>
            Are you sure you want to delete the <strong>{name}</strong> view?
            This only removes the view, not the rows.
          </p>
        </ConfirmationDialog>
      )}
    </>
  );
}

const ColumnsTrigger = buildDefaultTrigger(
  <FaTableColumns />,
  'Toggle properties',
);

/**
 * Dropdown that shows/hides the table's properties. A `DropdownMenu` rather
 * than its own popover so it matches every other menu here: whole-row targets,
 * a header saying what it does, and keyboard navigation for free. Rows keep the
 * menu open, since toggling several columns is the normal case.
 */
function ColumnsMenu({
  allColumns,
  columns,
  showColumn,
  hideColumn,
  lockedColumns,
  lockedReason,
  canWrite,
}: {
  allColumns: Property[];
  columns: Property[];
  showColumn: (subject: string) => void;
  hideColumn: (subject: string) => void;
  lockedColumns: ReadonlySet<string>;
  lockedReason: string;
  canWrite: boolean;
}): JSX.Element {
  const titles = usePropertyTitles(allColumns);
  const visible = useMemo(
    () => new Set(columns.map(c => c.subject)),
    [columns],
  );

  const items = useMemo((): DropdownItem[] => {
    if (allColumns.length === 0) {
      return [];
    }

    return [
      {
        id: 'columns-header',
        label: 'Toggle properties',
        header: true,
        onClick: () => undefined,
      },
      ...allColumns.map(column => {
        const locked = lockedColumns.has(column.subject);
        // A locked property is rendered by the view whatever the config says,
        // so it reads as shown regardless.
        const shown = locked || visible.has(column.subject);

        return {
          id: column.subject,
          label: titles.get(column.subject) ?? column.shortname,
          // A check on the shown ones, matching how the view-type section of
          // the tab menu marks its current choice.
          icon: shown ? <FaCheck /> : <CheckPlaceholder />,
          helper: locked
            ? lockedReason
            : shown
              ? 'Hide this property'
              : 'Show this property',
          disabled: locked,
          keepOpen: true,
          onClick: () =>
            shown ? hideColumn(column.subject) : showColumn(column.subject),
        };
      }),
    ];
  }, [
    allColumns,
    visible,
    showColumn,
    hideColumn,
    titles,
    lockedColumns,
    lockedReason,
  ]);

  if (!canWrite || items.length === 0) {
    return (
      <IconBtn disabled title='Toggle properties' type='button'>
        <FaTableColumns />
      </IconBtn>
    );
  }

  return (
    <DropdownMenu
      Trigger={ColumnsTrigger}
      items={items}
      // Only worth a filter box once scanning the list stops being instant.
      searchable={allColumns.length > 8}
    />
  );
}

const Bar = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  padding-block: 0.25rem;
`;

const Tabs = styled.div`
  display: flex;
  align-items: center;
  gap: 0.25rem;
`;

const Actions = styled.div`
  display: flex;
  align-items: center;
  gap: 0.25rem;
`;

const IconBtn = styled.button`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  height: 1.85rem;
  width: 1.85rem;
  border: none;
  border-radius: ${p => p.theme.radius};
  background-color: transparent;
  color: ${p => p.theme.colors.textLight};
  cursor: pointer;

  &:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  &:hover:not(:disabled) {
    background-color: ${p => p.theme.colors.bg1};
    color: ${p => p.theme.colors.text};
  }
`;

const Tab = styled.button<{ $active: boolean }>`
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  height: 1.85rem;
  padding: 0.1rem 0.7rem;
  border: none;
  border-radius: ${p => p.theme.radius};
  background-color: ${p => (p.$active ? p.theme.colors.bg1 : 'transparent')};
  color: ${p => (p.$active ? p.theme.colors.text : p.theme.colors.textLight)};
  font-weight: ${p => (p.$active ? 'bold' : 'normal')};
  cursor: pointer;
  white-space: nowrap;

  &:hover {
    background-color: ${p => p.theme.colors.bg1};
  }
`;

const TabInput = styled(InputStyled)`
  height: 1.85rem;
  width: 10rem;
  font-weight: bold;
`;

/** Keeps unchecked rows aligned with the checked ones. */
const CheckPlaceholder = styled.span`
  display: inline-block;
  width: 1em;
`;
