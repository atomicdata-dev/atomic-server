import {
  useCanWrite,
  useDrive,
  useResource,
  useStore,
  type Store,
} from '@tomic/react';
import { useCurrentSubject } from '../helpers/useCurrentSubject';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { useQueryScopeHandler } from '../hooks/useQueryScope';
import { useNewRoute } from '../helpers/useNewRoute';
import { useFavorites } from '../hooks/useFavorites';
import { useInlineTitleAffordances } from '../hooks/useInlineTitleAffordances';
import {
  newContextItem,
  useAISidebar,
} from '../components/AI/AISidebarContext';
import { type AIAtomicResourceMessageContext } from '@chunks/AI/types';
import type { ActionContext } from './types';

/** Capabilities and callbacks the consuming surface provides. */
export interface ActionContextOverrides {
  external?: boolean;
  showCodeUsageDialog?: () => void;
  openEmojiPicker?: () => void;
  openPluginRun?: () => void;
  pluginClass?: string;
  openCoverPicker?: () => void;
  onAfterDelete?: () => void;
  toggleSidebar?: () => void;
}

/** Fields needed to assemble an ActionContext outside a React render. */
export interface BuildActionContextInput {
  subject: string;
  store: Store;
  navigate: (to: string) => void;
  favorites: string[];
  addFavorite: (subject: string) => void;
  removeFavorite: (subject: string) => void;
  currentSubject?: string;
  drive?: string;
  addToChat?: () => void;
  enableScope?: () => void;
  addChild?: () => void;
  toggleSidebar?: () => void;
}

/**
 * Build an {@link ActionContext} from already-resolved store state — used by
 * AI tools, which run after the subject is known.
 */
export async function buildActionContext(
  input: BuildActionContextInput,
): Promise<ActionContext> {
  const resource = await input.store.getResource(input.subject);
  const agent = input.store.getAgent();
  let canWrite = false;

  if (agent?.subject) {
    if (resource.new) {
      canWrite = true;
    } else {
      const [allowed] = await resource.canWrite(agent.subject);
      canWrite =
        !!allowed ||
        (input.subject.startsWith('did:ad:') &&
          agent.subject.startsWith('did:ad:'));
    }
  }

  return {
    store: input.store,
    navigate: input.navigate,
    subject: input.subject,
    resource,
    canWrite,
    currentSubject: input.currentSubject,
    pathname: typeof window === 'undefined' ? '' : window.location.pathname,
    isFavorite: input.favorites.includes(input.subject),
    addFavorite: input.addFavorite,
    removeFavorite: input.removeFavorite,
    addToChat: input.addToChat ?? (() => undefined),
    enableScope: input.enableScope ?? (() => undefined),
    addChild: input.addChild ?? (() => undefined),
    drive: input.drive,
    titleAffordancesInline: false,
    toggleSidebar: input.toggleSidebar,
  };
}

/**
 * Assembles the {@link ActionContext} for a target resource — everything the
 * action definitions need at render (available/disabled/label) and run time.
 */
export function useActionContext(
  subject: string,
  overrides: ActionContextOverrides = {},
): ActionContext {
  const store = useStore();
  const navigate = useNavigateWithTransition();
  const resource = useResource(subject);
  const canWrite = useCanWrite(resource);
  const [currentSubject] = useCurrentSubject();
  const { enableScope } = useQueryScopeHandler(subject);
  const addChild = useNewRoute(subject);
  const [favorites, addFavorite, removeFavorite] = useFavorites();
  const { setContextItems, isOpen, setIsOpen } = useAISidebar();
  const [drive] = useDrive();
  const titleAffordancesInline = useInlineTitleAffordances();

  const addToChat = () => {
    setContextItems(prev => [
      ...prev.filter(
        x => x.type === 'atomic-resource' && x.subject !== subject,
      ),
      newContextItem({
        type: 'atomic-resource',
        subject,
      } as AIAtomicResourceMessageContext),
    ]);

    if (!isOpen) {
      setIsOpen(true);
    }
  };

  return {
    store,
    navigate,
    subject,
    resource,
    canWrite,
    currentSubject,
    pathname: window.location.pathname,
    isFavorite: favorites.includes(subject),
    addFavorite,
    removeFavorite,
    addToChat,
    enableScope,
    addChild,
    drive,
    titleAffordancesInline,
    ...overrides,
  };
}
