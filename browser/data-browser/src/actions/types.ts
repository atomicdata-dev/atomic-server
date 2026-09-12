import type { ReactNode } from 'react';
import type { Resource, Store } from '@tomic/react';

/**
 * Central action system (see planning/actions.md): each user-invocable action
 * on a resource is defined ONCE as an {@link ActionDefinition}, and every
 * surface — context menus, the searchable ⌘M menu, hotkeys, the ⌘K palette,
 * AI tools — is a projection of that definition.
 */

/** Whether the action targets a specific resource or the app as a whole. */
export type ActionScope = 'resource' | 'app';

/** Menus render a divider between consecutive items of different sections. */
export type ActionSection = 'view' | 'action';

/**
 * Everything an action may need at run time, assembled once per target by
 * `useActionContext`. Optional members are capabilities a surface may or may
 * not provide — actions requiring one hide themselves via `available` when
 * it's absent.
 */
export interface ActionContext {
  store: Store;
  navigate: (to: string) => void;
  /** The resource this action targets. */
  subject: string;
  resource: Resource;
  canWrite: boolean;
  /** Subject of the resource currently shown in the main view. */
  currentSubject: string | undefined;
  pathname: string;
  isFavorite: boolean;
  addFavorite: (subject: string) => void;
  removeFavorite: (subject: string) => void;
  addToChat: () => void;
  enableScope: () => void;
  addChild: () => void;
  /** Current drive subject, if any. */
  drive?: string;
  /**
   * The page title renders its own "Add icon" / "Add cover" buttons, so the
   * menu can tuck the matching actions away. False on touch and narrow
   * viewports, where the menu is the only way to reach them.
   */
  titleAffordancesInline: boolean;
  /** The subject lives on another server (e.g. shown via an AtomicLink). */
  external?: boolean;
  showCodeUsageDialog?: () => void;
  /** Opens the emoji picker dialog for this resource's icon. */
  openEmojiPicker?: () => void;
  /** Opens the pick-or-upload dialog for this resource's cover image. */
  openCoverPicker?: () => void;
  /** Runs a plugin and shows what it proposes before anything is written. */
  openPluginRun?: () => void;
  /** The drive's plugin class, once resolved. Absent while looking up. */
  pluginClass?: string;
  onAfterDelete?: () => void;
  /** App-level: lock or unlock the sidebar. */
  toggleSidebar?: () => void;
}

/** What the confirmation dialog for a `danger` action shows. */
export interface ActionConfirmation {
  title: (ctx: ActionContext) => string;
  confirmLabel: (ctx: ActionContext) => string;
  body: (ctx: ActionContext) => ReactNode;
}

/**
 * A single user-invocable action. Labels/helpers are functions so wuchale
 * extracts them for translation (module-level string literals are ignored).
 */
export interface ActionDefinition {
  /** Stable id; matches the historical `ContextMenuOptions` string values. */
  id: string;
  scope: ActionScope;
  section: ActionSection;
  label: (ctx: ActionContext) => string;
  /** Tooltip today; doubles as the AI/MCP tool description later. */
  helper: (ctx: ActionContext) => string;
  icon?: (ctx: ActionContext) => ReactNode;
  /** From the `shortcuts` registry; rendered as a chip wherever listed. */
  shortcut?: string;
  /**
   * Help-page wording when the menu label is too terse (e.g. menu says
   * "Edit", the shortcuts list says "Edit resource").
   */
  shortcutLabel?: (ctx: ActionContext) => string;
  /**
   * When true, the in-app AI tools (and a future MCP server) derive a tool
   * from this definition: `description` is `helper`, `execute` is `run`.
   */
  asTool?: boolean;
  /** Tool name when `asTool` is set. Defaults to the action id. */
  toolName?: string;
  /** Extra search terms for searchable surfaces (⌘M filter, ⌘K palette). */
  keywords?: string[];
  /**
   * Hidden from the default menu listing; only surfaces in searchable menus
   * while the filter query matches. For secondary actions that would clutter
   * the list. A function decides per context (e.g. only while the page
   * offers the action elsewhere).
   */
  searchOnly?: boolean | ((ctx: ActionContext) => boolean);
  /** Surfaces must confirm before running (unless explicitly bypassed). */
  danger?: boolean;
  /** Label shown while the confirmation bypass (shift) is held. */
  dangerLabel?: (ctx: ActionContext) => string;
  confirmation?: ActionConfirmation;
  /** Hidden entirely when false. */
  available?: (ctx: ActionContext) => boolean;
  /** Shown greyed out when true. */
  disabled?: (ctx: ActionContext) => boolean;
  /** The one implementation every surface invokes. */
  run: (ctx: ActionContext) => void | Promise<void>;
}
