import toast from 'react-hot-toast';
import { canvas, core, dataBrowser, forks, server } from '@tomic/react';
import {
  FaArrowUpRightFromSquare,
  FaClock,
  FaCode,
  FaCodeBranch,
  FaCodeMerge,
  FaDownload,
  FaFaceSmile,
  FaImage,
  FaMagnifyingGlass,
  FaMessage,
  FaPencil,
  FaPlus,
  FaRegStar,
  FaShare,
  FaStar,
  FaTrash,
  FaTurnUp,
} from 'react-icons/fa6';
import { atomicArgu } from '../ontologies/atomic-argu';
import { getOrCreateForksFolder } from '../helpers/forksFolder';
import {
  constructOpenURL,
  dataURL,
  editURL,
  historyURL,
  importerURL,
  shareURL,
} from '../helpers/navigation';
import { paths } from '../routes/paths';
import { shortcuts } from './shortcuts';
import type { ActionContext, ActionDefinition } from './types';

const getParent = (ctx: ActionContext): string | undefined =>
  ctx.resource.get(core.properties.parent) as string | undefined;

/**
 * All actions on a resource, in menu order. Ids keep the historical
 * `ContextMenuOptions` values so `showOnly` call sites and `menu-item-<id>`
 * test ids stay valid.
 */
export const resourceActions: ActionDefinition[] = [
  {
    id: 'view',
    scope: 'resource',
    section: 'view',
    label: () => 'Normal View',
    helper: () => 'Open the regular, default View.',
    keywords: ['show', 'open'],
    disabled: ctx => ctx.pathname.startsWith(paths.show),
    run: ctx => ctx.navigate(constructOpenURL(ctx.subject)),
  },
  {
    id: 'data',
    scope: 'resource',
    section: 'view',
    label: () => 'Data View',
    helper: () => 'View the resource and its properties in the Data View.',
    keywords: ['json', 'raw', 'properties'],
    shortcut: shortcuts.data,
    shortcutLabel: () => 'Show data view',
    disabled: ctx => ctx.pathname.startsWith(paths.data),
    run: ctx => ctx.navigate(dataURL(ctx.subject)),
  },
  {
    id: 'favorite',
    scope: 'resource',
    section: 'action',
    label: ctx =>
      ctx.isFavorite ? 'Remove from favorites' : 'Add to favorites',
    helper: () => 'Toggle whether this resource appears in your Favorites.',
    keywords: ['star', 'bookmark', 'pin'],
    icon: ctx => (ctx.isFavorite ? <FaStar /> : <FaRegStar />),
    asTool: true,
    toolName: 'favorite_resource',
    run: ctx =>
      ctx.isFavorite
        ? ctx.removeFavorite(ctx.subject)
        : ctx.addFavorite(ctx.subject),
  },
  {
    id: 'open',
    scope: 'resource',
    section: 'action',
    label: () => 'Open',
    helper: () => 'Open the resource',
    icon: () => <FaArrowUpRightFromSquare />,
    available: ctx => !!ctx.external,
    run: ctx => ctx.navigate(constructOpenURL(ctx.subject)),
  },
  {
    id: 'edit',
    scope: 'resource',
    section: 'action',
    label: () => 'Edit',
    helper: () => 'Open the edit form.',
    keywords: ['change', 'modify', 'form'],
    icon: () => <FaPencil />,
    shortcut: shortcuts.edit,
    shortcutLabel: () => 'Edit resource',
    available: ctx => ctx.canWrite,
    run: ctx => ctx.navigate(editURL(ctx.subject)),
  },
  {
    id: 'setEmoji',
    scope: 'resource',
    section: 'action',
    label: ctx =>
      (ctx.resource.get(dataBrowser.properties.emoji) ??
      ctx.resource.get(dataBrowser.properties.icon))
        ? 'Change icon'
        : 'Add icon',
    helper: () =>
      'Pick an emoji or image shown next to this resource wherever it appears.',
    keywords: [
      'emoji',
      'icon',
      'glyph',
      'smiley',
      'avatar',
      'image',
      'picture',
      'profile',
      'decorate',
    ],
    icon: () => <FaFaceSmile />,
    // Inline title buttons cover this on desktop; on touch and narrow
    // viewports the menu is the only entry point, so list it.
    searchOnly: ctx => ctx.titleAffordancesInline,
    available: ctx => ctx.canWrite && ctx.openEmojiPicker !== undefined,
    run: ctx => ctx.openEmojiPicker?.(),
  },
  {
    id: 'setCover',
    scope: 'resource',
    section: 'action',
    label: ctx =>
      (ctx.resource.get(dataBrowser.properties.coverImage) ??
      ctx.resource.get(atomicArgu.properties.coverImage))
        ? 'Change cover'
        : 'Add cover',
    helper: () =>
      'Pick an image shown as a banner at the top of this resource.',
    keywords: ['cover', 'banner', 'image', 'header', 'photo', 'decorate'],
    icon: () => <FaImage />,
    // Inline title buttons cover this on desktop; on touch and narrow
    // viewports the menu is the only entry point, so list it.
    searchOnly: ctx => ctx.titleAffordancesInline,
    available: ctx => ctx.canWrite && ctx.openCoverPicker !== undefined,
    run: ctx => ctx.openCoverPicker?.(),
  },
  {
    id: 'editAsFork',
    scope: 'resource',
    section: 'action',
    label: () => 'Edit as fork',
    helper: () =>
      'Fork this resource. The original is untouched until you merge the fork back.',
    keywords: ['fork', 'draft', 'suggest', 'propose', 'copy', 'branch'],
    icon: () => <FaCodeBranch />,
    // A Drive is a container, not content: forking one would copy its ACL and
    // its whole shape, which is meaningless as a proposed change. A Canvas keeps
    // its content in Loro stroke lists (not the `doc` container the fork seeds),
    // so forking one would lose the body — gate it off until canvas gets its own
    // fork/merge.
    available: ctx =>
      ctx.canWrite &&
      !ctx.resource.isFork &&
      !ctx.resource.getClasses().includes(server.classes.drive) &&
      !ctx.resource.getClasses().includes(canvas.classes.canvas) &&
      !!ctx.drive,
    run: async ctx => {
      try {
        const forksFolder = await getOrCreateForksFolder(ctx.store, ctx.drive!);
        const fork = await ctx.resource.fork(forksFolder);
        toast.success('Fork created');
        ctx.navigate(constructOpenURL(fork.subject));
      } catch (error) {
        toast.error((error as Error).message);
      }
    },
  },
  {
    id: 'mergeFork',
    scope: 'resource',
    section: 'action',
    label: () => 'Merge fork',
    helper: () =>
      'Write this fork onto the resource it was forked from, as a single commit.',
    keywords: ['merge', 'publish', 'apply', 'accept', 'fork', 'draft'],
    icon: () => <FaCodeMerge />,
    available: ctx => ctx.resource.isFork,
    run: async ctx => {
      try {
        const original = await ctx.resource.mergeIntoOriginal();
        toast.success('Fork merged');
        ctx.navigate(constructOpenURL(original.subject));
      } catch (error) {
        toast.error((error as Error).message);
      }
    },
  },
  {
    id: 'openOriginal',
    scope: 'resource',
    section: 'view',
    label: () => 'Open original',
    helper: () => 'Open the resource this fork was forked from.',
    keywords: ['original', 'source', 'fork', 'draft'],
    icon: () => <FaTurnUp />,
    available: ctx => ctx.resource.isFork,
    run: ctx => {
      const original = ctx.resource.get(forks.properties.originalSubject);

      if (original) {
        ctx.navigate(constructOpenURL(original));
      }
    },
  },
  {
    id: 'newChild',
    scope: 'resource',
    section: 'action',
    label: () => 'Add child',
    helper: () => 'Create a new resource under this resource.',
    keywords: ['new', 'create'],
    icon: () => <FaPlus />,
    available: ctx => ctx.canWrite,
    run: ctx => ctx.addChild(),
  },
  {
    id: 'useInCode',
    scope: 'resource',
    section: 'action',
    label: () => 'Use in code',
    helper: () =>
      'Usage instructions for how to fetch and use the resource in your code.',
    keywords: ['developer', 'snippet', 'api'],
    icon: () => <FaCode />,
    available: ctx => !!ctx.showCodeUsageDialog,
    run: ctx => ctx.showCodeUsageDialog?.(),
  },
  {
    id: 'addToChat',
    scope: 'resource',
    section: 'action',
    label: () => 'Add to chat',
    helper: () => 'Add the resource as context to the AI sidebar',
    keywords: ['ai', 'assistant', 'context'],
    icon: () => <FaMessage />,
    run: ctx => ctx.addToChat(),
  },
  {
    id: 'scope',
    scope: 'resource',
    section: 'action',
    label: () => 'Search children',
    helper: () => 'Scope search to resource',
    keywords: ['find', 'filter'],
    icon: () => <FaMagnifyingGlass />,
    run: ctx => ctx.enableScope(),
  },
  {
    id: 'share',
    scope: 'resource',
    section: 'action',
    label: () => 'Permissions & Invites',
    helper: () => 'Edit permissions and create invites.',
    keywords: ['share', 'access', 'rights', 'invite'],
    icon: () => <FaShare />,
    asTool: true,
    toolName: 'open_share_settings',
    run: ctx => ctx.navigate(shareURL(ctx.subject)),
  },
  {
    id: 'history',
    scope: 'resource',
    section: 'action',
    label: () => 'History',
    helper: () => 'Show the history of this resource',
    keywords: ['versions', 'changes', 'undo'],
    icon: () => <FaClock />,
    asTool: true,
    toolName: 'show_history',
    run: ctx => ctx.navigate(historyURL(ctx.subject)),
  },
  {
    id: 'parent',
    scope: 'resource',
    section: 'action',
    label: () => 'Go to parent',
    helper: () => 'Open the parent of this resource.',
    keywords: ['up', 'back', 'enclosing', 'folder'],
    icon: () => <FaTurnUp />,
    shortcut: shortcuts.parent,
    shortcutLabel: () => 'Go to parent',
    // Not just `!!getParent`: a stub after goBack can lack `parent` while
    // the table is already on screen. Dropping the action there ate Cmd+Up.
    // Drives have no parent — hide it once we know that's what this is.
    available: ctx =>
      !!getParent(ctx) ||
      !ctx.resource.getClasses().includes(server.classes.drive),
    run: async ctx => {
      let parent = getParent(ctx);

      if (!parent) {
        const resource = await ctx.store.getResource(ctx.subject);
        parent = resource.get(core.properties.parent) as string | undefined;
      }

      if (parent) {
        ctx.navigate(constructOpenURL(parent));
      }
    },
  },
  {
    id: 'import',
    scope: 'resource',
    section: 'action',
    label: () => 'Import',
    helper: () => 'Import Atomic Data to this resource',
    keywords: ['upload', 'json'],
    icon: () => <FaDownload />,
    available: ctx => ctx.canWrite,
    run: ctx => ctx.navigate(importerURL(ctx.subject)),
  },
  {
    id: 'delete',
    scope: 'resource',
    section: 'action',
    label: () => 'Delete',
    helper: () => 'Delete this resource.',
    keywords: ['remove', 'destroy', 'trash'],
    icon: () => <FaTrash />,
    available: ctx => ctx.canWrite,
    asTool: true,
    toolName: 'delete_resource',
    danger: true,
    dangerLabel: () => 'Confirm Delete',
    confirmation: {
      title: () => 'Delete resource',
      confirmLabel: () => 'Delete',
      body: ctx => (
        <p>
          Are you sure you want to delete {ctx.resource.title || ctx.subject}?
        </p>
      ),
    },
    run: async ctx => {
      const parent = getParent(ctx);

      try {
        await ctx.resource.destroy();
        ctx.onAfterDelete?.();
        toast.success('Resource deleted!');

        if (ctx.currentSubject === ctx.subject) {
          ctx.navigate(parent ? constructOpenURL(parent) : '/');
        }
      } catch (error) {
        // A failed delete is the one that most needs saying so: `destroy()`
        // throws before it removes the resource locally, so the row stays in
        // the tree and the only thing distinguishing "deleted" from "refused"
        // is this message. It used to read `(error as Error).message`, which is
        // `undefined` for anything thrown that isn't an Error — an empty toast,
        // i.e. a delete that silently did nothing.
        const detail =
          error instanceof Error && error.message
            ? error.message
            : typeof error === 'string' && error
              ? error
              : 'unknown error';

        console.error('[delete] destroy failed for', ctx.subject, error);
        toast.error(`Could not delete: ${detail}`);
      }
    },
  },
];
