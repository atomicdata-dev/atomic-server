import { useEffect, useRef, useState, type JSX, useMemo } from 'react';
import { useHotkeys } from 'react-hotkeys-hook';
import { styled } from 'styled-components';
import { displayShortcut, shortcuts } from '../actions/shortcuts';
import { listShortcutHelp } from '../actions/catalog';
import {
  matchActionsForPalette,
  PALETTE_MIN_QUERY_LENGTH,
} from '../actions/matchActions';
import { useAppMenuItems } from '../actions/appMenuItems';
import { isItem, matchesQuery, type MenuItemMinimial } from './Dropdown';
import { resourceActions } from '../actions/resourceActions';
import { runAction } from '../actions/runAction';
import { useActionContext } from '../actions/useActionContext';
import type { ActionDefinition } from '../actions/types';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { constructOpenURL } from '../helpers/navigation';
import { useCurrentSubject } from '../helpers/useCurrentSubject';
import {
  ConfirmationDialog,
  ConfirmationDialogTheme,
} from './ConfirmationDialog';
import { ResourceInline } from '../views/ResourceInline';
import { ResourceUsage } from './ResourceUsage';
import {
  useServerSearch,
  useStore,
  ai,
  core,
  dataBrowser,
  useArray,
  useResource,
  useResources,
  useString,
  useTitle,
  type Ai,
  type DataBrowser,
  type Resource,
  type Server,
  type Store,
} from '@tomic/react';
import { useSettings } from '../helpers/AppSettings';
import { usePrivateDrive } from '../hooks/usePrivateDrive';
import { useQueryScopeHandler } from '../hooks/useQueryScope';
import { Column, Row } from './Row';
import { ErrorBoundary } from '../views/ErrorPage';
import { ErrorLook } from './ErrorLook';

import { InlineFormattedResourceList } from './InlineFormattedResourceList';
import { FaMagnifyingGlass, FaComments } from 'react-icons/fa6';
import ResourceCard from '../views/Card/ResourceCard';
import ResourceRow from '@views/ResourceRow';
import { ChatMatchRow } from '../routes/Search/ChatMatchRow';
import { useChatMatches } from '../routes/Search/useChatMatches';
import { DEFAULT_AICHAT_NAME } from './AI/aiContstants';
import { setPendingFirstMessage } from '@chunks/AI/pendingFirstMessage';
import {
  closeOverlay,
  openSearchOverlay,
  openShortcutsOverlay,
  setOverlay,
  subscribeOverlay,
  pendingSearchOverlayQuery,
  pendingSearchOverlayScope,
  type OverlayType,
} from './overlayState';
import { getRecentResources } from '../helpers/recentResources';
import { useDocumentText } from '../hooks/useDocumentText';
import { getSearchResultHint } from '../helpers/searchResultHint';

export { closeOverlay, openSearchOverlay, openShortcutsOverlay };

// ─── Module-level search state (shared between SearchOverlay and PreviewPane) ───

let searchResults: string[] = [];
let searchSelectedIndex = 0;
const previewListeners = new Set<
  (isOpen: boolean, results: string[], index: number) => void
>();

export function setSearchResults(results: string[], index: number): void {
  searchResults = results;
  searchSelectedIndex = index;
  previewListeners.forEach(listener =>
    listener(searchResults.length > 0, searchResults, searchSelectedIndex),
  );
}

// ─── Backdrop + Panel ─────────────────────────────────────────────────────────

const OverlayBackdrop = styled.div`
  position: fixed;
  inset: 0;
  z-index: 999;
  background: rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(6px);
  animation: fadeIn 100ms ease-out;

  @keyframes fadeIn {
    from {
      opacity: 0;
    }
    to {
      opacity: 1;
    }
  }
`;

const OverlayPanel = styled.div`
  position: fixed;
  top: 15vh;
  left: 50%;
  transform: translateX(-50%);
  z-index: 999;
  width: 100%;
  max-width: 30rem;
  height: 30rem;
  display: flex;
  flex-direction: column;
  background: ${p => p.theme.colors.bg};
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  box-shadow: ${p => p.theme.boxShadow};
  animation: slideIn 100ms ease-out;
  overflow: visible;

  @keyframes slideIn {
    from {
      transform: translate(-50%, -20px);
      opacity: 0;
    }
    to {
      transform: translate(-50%, 0);
      opacity: 1;
    }
  }
`;

const OverlayInputWrapper = styled.div`
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 1rem;
  border-bottom: 1px solid ${p => p.theme.colors.bg2};
  color: ${p => p.theme.colors.textLight};
`;

const OverlayInput = styled.input`
  flex: 1;
  background: transparent;
  border: none;
  font-size: 1.125rem;
  color: ${p => p.theme.colors.text};
  outline: none;

  &::placeholder {
    color: ${p => p.theme.colors.textLight};
  }
`;

const ShortcutHint = styled.kbd`
  padding: 0.2rem 0.4rem;
  background: ${p => p.theme.colors.bg1};
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: 0.25rem;
  font-size: 0.75rem;
  color: ${p => p.theme.colors.textLight};
  cursor: pointer;
`;

const PanelContent = styled.div`
  flex: 1;
  overflow-y: auto;
  min-height: 0;
`;

const ResultsList = styled.div`
  display: flex;
  flex-direction: column;
`;

const ResultsArea = styled.div`
  flex: 1;
`;

const TagHeading = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-weight: 600;
  font-size: 0.75rem;
  text-transform: uppercase;
`;

const FooterRow = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.75rem 1rem;
  border-top: 1px solid ${p => p.theme.colors.bg2};
  color: ${p => p.theme.colors.textLight};
  font-size: 0.75rem;
  background: ${p => p.theme.colors.bg};
  border-bottom-left-radius: inherit;
  border-bottom-right-radius: inherit;
`;

const FooterHints = styled.div`
  display: flex;
  gap: 1rem;

  kbd {
    background: ${p => p.theme.colors.bg1};
    border: 1px solid ${p => p.theme.colors.bg2};
    border-radius: 0.2rem;
    padding: 0.1rem 0.3rem;
    font-family: inherit;
  }
`;

const PreviewFloat = styled.div`
  position: absolute;
  top: 0;
  right: -1rem;
  transform: translateX(100%);
  z-index: 1000;
  width: 18rem;
  height: 30rem;
  overflow-y: auto;

  /* Panel (30rem) is centered, so the preview needs 32rem on each side of the
     viewport center. Hide it when it would be cut off by the screen edge. */
  @media (max-width: 66rem) {
    display: none;
  }
`;

const SectionHeading = styled.div`
  padding: 0.5rem 1rem 0.25rem;
  font-size: 0.7rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: ${p => p.theme.colors.textLight};
`;

const ActionRow = styled.button<{ $selected?: boolean }>`
  display: flex;
  align-items: center;
  width: 100%;
  gap: 0.75rem;
  padding: 0.65rem 1rem;
  border: none;
  border-bottom: 1px solid ${p => p.theme.colors.bg2};
  background: ${p => (p.$selected ? p.theme.colors.bg1 : 'transparent')};
  color: ${p => p.theme.colors.text};
  font-size: 0.875rem;
  cursor: pointer;
  text-align: left;
  transition: background 80ms;

  &:hover {
    background: ${p => p.theme.colors.bg1};
  }

  svg {
    color: ${p => p.theme.colors.textLight};
    flex-shrink: 0;
  }

  span {
    flex: 1;
  }
`;

const ActionShortcut = styled.kbd`
  background: ${p => p.theme.colors.bg1};
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: 0.2rem;
  padding: 0.1rem 0.3rem;
  font-size: 0.7rem;
  color: ${p => p.theme.colors.textLight};
  font-family: inherit;
`;

const AIChatRow = styled.button<{ $selected?: boolean }>`
  display: flex;
  align-items: center;
  width: 100%;
  gap: 0.75rem;
  padding: 0.75rem 1rem;
  border: none;
  border-bottom: 1px solid ${p => p.theme.colors.bg2};
  background: ${p => (p.$selected ? p.theme.colors.bg1 : 'transparent')};
  color: ${p => p.theme.colors.text};
  font-size: 0.875rem;
  cursor: pointer;
  text-align: left;
  transition: background 80ms;

  &:hover {
    background: ${p => p.theme.colors.bg1};
  }

  span {
    flex: 1;
  }

  svg {
    color: ${p => p.theme.colors.main};
    flex-shrink: 0;
  }
`;

// ─── Search Overlay ────────────────────────────────────────────────────────────

const tagTokenRegex = /\btag:([\w-]+)/g;

function parseSearchTags(
  query: string,
  tagResources: Map<string, { title: string }>,
): { searchQuery: string; tagSubjects: string[] } {
  const tagSubjects = new Set<string>();

  for (const match of query.matchAll(tagTokenRegex)) {
    const tagTitle = match[1].toLowerCase();

    for (const [subject, tag] of tagResources) {
      if (tag.title.toLowerCase() === tagTitle) {
        tagSubjects.add(subject);
        break;
      }
    }
  }

  return {
    searchQuery: query.replace(tagTokenRegex, '').trim(),
    tagSubjects: [...tagSubjects],
  };
}

type PaletteRow =
  | { kind: 'action'; action: ActionDefinition }
  | { kind: 'place'; item: MenuItemMinimial }
  | { kind: 'chat'; subject: string }
  | { kind: 'result'; subject: string }
  | { kind: 'aiChat' };

function SearchOverlay(): JSX.Element {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const { drive } = useSettings();
  const { privateDrive } = usePrivateDrive();
  const { scope: urlScope } = useQueryScopeHandler();
  // "Search children" opens this palette limited to one resource; the chip
  // under the input shows that and can lift it.
  const [scopeOverride, setScopeOverride] = useState<string | null>(
    () => pendingSearchOverlayScope() ?? null,
  );
  const scope = scopeOverride ?? urlScope;
  const scopeResource = useResource(scope || undefined);
  const navigate = useNavigateWithTransition();
  const store = useStore();
  const [currentSubject] = useCurrentSubject();
  const actionCtx = useActionContext(currentSubject ?? '');
  const [confirmingAction, setConfirmingAction] = useState<ActionDefinition>();
  const driveResource = useResource<Server.Drive>(drive);
  const [driveTags] = useArray(driveResource, dataBrowser.properties.tagList);
  const tagResources = useResources(driveTags);

  const handleStartAIChat = async (
    q: string,
    s: Store,
    d: string,
    n: (url: string) => void,
  ): Promise<void> => {
    const chatResource = await s.newResource<Ai.AiChat>({
      parent: d,
      isA: ai.classes.aiChat,
      propVals: {
        [core.properties.name]: DEFAULT_AICHAT_NAME,
      },
    });

    await chatResource.save();

    // The chat has no messages yet, so the query can't be attached to one
    // until AIChatPage mounts — hand it off via the pending-first-message
    // map instead of (incorrectly) using it as the chat's title.
    const trimmed = q.trim();

    if (trimmed) {
      setPendingFirstMessage(chatResource.subject, trimmed);
    }

    n(constructOpenURL(chatResource.subject));
  };

  const resultsRef = useRef<HTMLDivElement | null>(null);

  const [query, setQuery] = useState(pendingSearchOverlayQuery);
  const [selectedIndex, setSelected] = useState(0);

  const { searchQuery, tagSubjects } = useMemo(
    () => parseSearchTags(query, tagResources),
    [query, tagResources],
  );
  const filters: Record<string, string[]> =
    tagSubjects.length > 0
      ? { [dataBrowser.properties.tags]: tagSubjects }
      : {};
  const filterIsEmpty = Object.keys(filters).length === 0;
  const tags = tagSubjects;

  const { results, error } = useServerSearch(searchQuery, {
    debounce: 0,
    parents: scope || drive,
    include: true,
    filters,
    limit: 10,
    allowEmptyQuery: !filterIsEmpty,
  });

  // Nothing typed yet: offer what was opened recently, most recent first,
  // minus the page already open.
  const showRecent = !query.trim() && filterIsEmpty && !scope;
  // DMs and AI chats are not in the drive, so the server cannot find them.
  const chatMatches = useChatMatches(searchQuery, !scope && filterIsEmpty);
  const chatSubjects = new Set(chatMatches.map(match => match.subject));
  const listed = showRecent
    ? getRecentResources(drive)
        .filter(subject => subject !== currentSubject)
        .slice(0, 8)
    : results.filter(subject => !chatSubjects.has(subject));

  const actionHits = currentSubject
    ? matchActionsForPalette(query, resourceActions, actionCtx)
    : [];
  // The app's own places and starts (Settings, Switch drive, New resource…),
  // the same ones the More menu lists, so Cmd+K reaches them from any page.
  const appMenu = useAppMenuItems();
  const placeNeedle = query.trim().toLowerCase();
  const placeHits =
    placeNeedle.length >= PALETTE_MIN_QUERY_LENGTH
      ? [...appMenu.create, ...appMenu.find].filter(
          (item): item is MenuItemMinimial =>
            isItem(item) &&
            !item.header &&
            !item.disabled &&
            matchesQuery(item, placeNeedle),
        )
      : [];
  const commandCount = actionHits.length + placeHits.length;
  // Chats sit between the commands and the drive's results.
  const chatCount = chatMatches.length;
  const resultOffset = commandCount + chatCount;
  const total =
    results.filter(subject => !chatSubjects.has(subject)).length + chatCount;
  const showAIChatRow = !!privateDrive && query && results.length === 0;
  const rows: PaletteRow[] = [
    ...actionHits.map(action => ({ kind: 'action' as const, action })),
    ...placeHits.map(item => ({ kind: 'place' as const, item })),
    ...chatMatches.map(({ subject }) => ({ kind: 'chat' as const, subject })),
    ...listed.map(subject => ({ kind: 'result' as const, subject })),
    ...(showAIChatRow ? [{ kind: 'aiChat' as const }] : []),
  ];
  const totalItemCount = rows.length;

  useEffect(() => {
    const timer = setTimeout(() => inputRef.current?.focus(), 50);

    return () => clearTimeout(timer);
  }, []);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setQuery(e.target.value);
    setSelected(0);
  };

  const activateRow = async (row: PaletteRow | undefined): Promise<void> => {
    if (!row) {
      return;
    }

    if (row.kind === 'action') {
      if (row.action.danger && row.action.confirmation) {
        setConfirmingAction(row.action);

        return;
      }

      runAction(row.action, actionCtx);
      closeOverlay();

      return;
    }

    if (row.kind === 'place') {
      closeOverlay();
      row.item.onClick();

      return;
    }

    if (row.kind === 'result' || row.kind === 'chat') {
      navigate(constructOpenURL(row.subject));
      closeOverlay();

      return;
    }

    if (privateDrive) {
      await handleStartAIChat(query, store, privateDrive, navigate);
      closeOverlay();
    }
  };

  const handleKeyDown = async (e: React.KeyboardEvent<HTMLInputElement>) => {
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setSelected(prev => (prev >= totalItemCount - 1 ? prev : prev + 1));
        break;
      case 'ArrowUp':
        e.preventDefault();
        setSelected(prev => (prev > 0 ? prev - 1 : 0));
        break;
      case 'Enter':
        e.preventDefault();
        await activateRow(rows[selectedIndex]);
        break;
      case 'Escape':
        e.preventDefault();
        closeOverlay();
        break;
    }
  };

  // Shift+Enter always starts an AI chat
  useHotkeys(
    'shift+enter',
    e => {
      e.preventDefault();

      if (!privateDrive) {
        return;
      }

      void (async () => {
        await handleStartAIChat(query, store, privateDrive, navigate);
        closeOverlay();
      })();
    },
    { enableOnFormTags: ['INPUT'] },
    [query, store, privateDrive, navigate],
  );

  useEffect(() => {
    if (selectedIndex >= 0 && resultsRef.current) {
      const el = resultsRef.current.querySelector(
        `[data-index="${selectedIndex}"]`,
      ) as HTMLElement | null;
      el?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  }, [selectedIndex]);

  // Sync results + index to module state for the preview. Actions are not
  // previewed — an action at selectedIndex 0 must not show results[0].
  useEffect(() => {
    const resultIndex =
      selectedIndex >= resultOffset &&
      selectedIndex < resultOffset + listed.length
        ? selectedIndex - resultOffset
        : -1;
    setSearchResults(listed, resultIndex);
  }, [listed, selectedIndex, resultOffset]);

  return (
    <ErrorBoundary>
      <OverlayInputWrapper>
        <FaMagnifyingGlass size={16} />
        <OverlayInput
          ref={inputRef}
          value={query}
          onChange={handleInputChange}
          onKeyDown={handleKeyDown}
          placeholder='Search for resources...'
          autoComplete='off'
          autoCorrect='off'
          autoCapitalize='off'
          spellCheck={false}
        />
        <ShortcutHint onClick={closeOverlay}>esc</ShortcutHint>
      </OverlayInputWrapper>

      {scope && (
        <ScopeChip data-testid='search-scope'>
          <span>Searching in {scopeResource.title}</span>
          <ScopeClear
            type='button'
            title='Search everywhere'
            aria-label='Search everywhere'
            onClick={() => {
              setScopeOverride('');
              inputRef.current?.focus();
            }}
          >
            ×
          </ScopeClear>
        </ScopeChip>
      )}
      {error ? (
        <ErrorLook style={{ padding: '1rem' }}>{error.message}</ErrorLook>
      ) : (
        <>
          {tags.length > 0 && (
            <Row
              center
              gap='1ch'
              style={{
                padding: '0.5rem 1rem',
                borderBottom: '1px solid',
                fontSize: '0.875rem',
              }}
            >
              <TagHeading>With Tags:</TagHeading>
              <InlineFormattedResourceList subjects={tags} />
            </Row>
          )}

          <PanelContent>
            <ResultsList>
              <ResultsArea ref={resultsRef}>
                <Column gap='0'>
                  {commandCount > 0 && <SectionHeading>Actions</SectionHeading>}
                  {actionHits.map((action, index) => (
                    <ActionRow
                      key={action.id}
                      data-index={index}
                      data-testid={`palette-action-${action.id}`}
                      $selected={index === selectedIndex}
                      onClick={() => {
                        setSelected(index);
                        void activateRow({ kind: 'action', action });
                      }}
                    >
                      {action.icon?.(actionCtx)}
                      <span>{action.label(actionCtx)}</span>
                      {action.shortcut && (
                        <ActionShortcut>
                          {displayShortcut(action.shortcut)}
                        </ActionShortcut>
                      )}
                    </ActionRow>
                  ))}
                  {placeHits.map((item, placeIndex) => {
                    const index = actionHits.length + placeIndex;

                    return (
                      <ActionRow
                        key={item.id}
                        data-index={index}
                        data-testid={`palette-action-${item.id}`}
                        $selected={index === selectedIndex}
                        onClick={() => {
                          setSelected(index);
                          void activateRow({ kind: 'place', item });
                        }}
                      >
                        {item.icon}
                        <span>{item.label}</span>
                      </ActionRow>
                    );
                  })}
                  {chatCount > 0 && <SectionHeading>Chats</SectionHeading>}
                  {chatMatches.map((match, chatIndex) => {
                    const index = commandCount + chatIndex;

                    return (
                      <ChatMatchRow
                        key={match.subject}
                        match={match}
                        index={index}
                        selected={index === selectedIndex}
                        onClick={() => {
                          setSelected(index);
                          void activateRow({
                            kind: 'chat',
                            subject: match.subject,
                          });
                        }}
                      />
                    );
                  })}
                  {showRecent && listed.length > 0 && (
                    <SectionHeading>Recently opened</SectionHeading>
                  )}
                  {!showRecent && listed.length > 0 && resultOffset > 0 && (
                    <SectionHeading>Resources</SectionHeading>
                  )}
                  {listed.map((subject, resultIndex) => {
                    const index = resultOffset + resultIndex;

                    return (
                      <ResultCard
                        key={subject}
                        query={searchQuery}
                        subject={subject}
                        index={index}
                        selected={index === selectedIndex}
                        onSelect={() => {
                          setSelected(index);
                          setTimeout(() => {
                            void activateRow({ kind: 'result', subject });
                          }, 80);
                        }}
                      />
                    );
                  })}
                  {showAIChatRow && (
                    <AIChatRow
                      data-index={resultOffset + listed.length}
                      $selected={selectedIndex === resultOffset + listed.length}
                      onClick={async () => {
                        if (!privateDrive) {
                          return;
                        }

                        await handleStartAIChat(
                          query,
                          store,
                          privateDrive,
                          navigate,
                        );
                        closeOverlay();
                      }}
                    >
                      <FaComments size={16} />
                      <span>Start AI Chat with "{query}"</span>
                    </AIChatRow>
                  )}
                </Column>
              </ResultsArea>
            </ResultsList>
          </PanelContent>

          <FooterRow>
            <FooterHints>
              <span>
                <kbd>↑</kbd> <kbd>↓</kbd> navigate
              </span>
              <span>
                <kbd>↵</kbd> open / run
              </span>
              <span>
                <kbd>⇧↵</kbd> chat
              </span>
              <span>
                <kbd>esc</kbd> close
              </span>
            </FooterHints>
            {total > 0 && (
              <span>
                {total} result{total !== 1 ? 's' : ''}
              </span>
            )}
          </FooterRow>
        </>
      )}
      <ConfirmationDialog
        title={confirmingAction?.confirmation?.title(actionCtx) ?? ''}
        show={confirmingAction !== undefined}
        bindShow={show => {
          if (!show) {
            setConfirmingAction(undefined);
          }
        }}
        theme={ConfirmationDialogTheme.Alert}
        confirmLabel={confirmingAction?.confirmation?.confirmLabel(actionCtx)}
        onConfirm={() => {
          if (confirmingAction) {
            runAction(confirmingAction, actionCtx);
            closeOverlay();
          }
        }}
      >
        {confirmingAction?.id === 'delete' ? (
          <>
            <p>
              Are you sure you want to delete{' '}
              <ResourceInline subject={actionCtx.subject} />
            </p>
            <ResourceUsage resource={actionCtx.resource} />
          </>
        ) : (
          confirmingAction?.confirmation?.body(actionCtx)
        )}
      </ConfirmationDialog>
    </ErrorBoundary>
  );
}

interface ResultCardProps {
  subject: string;
  query: string;
  index: number;
  selected: boolean;
  onSelect: () => void;
}

function CardPreview({ subject }: { subject: string }): JSX.Element {
  const [currentSubject] = useCurrentSubject();
  // Skip rendering the preview card if it's the same resource as the current page
  // to avoid duplicate view-transition-name conflicts.
  const skipCard = subject === currentSubject;

  return (
    <div
      style={{
        position: 'sticky',
        top: 0,
      }}
    >
      {skipCard ? null : <ResourceCard subject={subject} />}
    </div>
  );
}

const ResultRowWrapper = styled.div<{ $selected?: boolean }>`
  display: block;
  width: 100%;
  cursor: pointer;
  padding: 0.75rem 1rem;
  border-bottom: 1px solid ${p => p.theme.colors.bg2};
  background: ${p => (p.$selected ? p.theme.colors.bg1 : 'transparent')};
  transition: background 80ms;
`;

const ResultHintLine = styled.div`
  margin-top: 0.35rem;
  color: ${p => p.theme.colors.textLight};
  font-size: 0.75rem;
  line-height: 1.35;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;

  strong {
    color: ${p => p.theme.colors.text};
    font-weight: 600;
  }

  mark {
    border-radius: 0.15rem;
    background: ${p => p.theme.colors.main}22;
    color: inherit;
    font-weight: 600;
  }
`;

function SearchResultHint({
  subject,
  query,
}: {
  subject: string;
  query: string;
}): JSX.Element | null {
  const resource = useResource(subject) as Resource<
    DataBrowser.DocumentV2 | DataBrowser.Meeting
  >;
  const [title] = useTitle(resource);
  const [description] = useString(resource, core.properties.description);
  const document = useDocumentText(resource);
  const hint = useMemo(
    () => getSearchResultHint(query, { title, description, document }),
    [query, title, description, document],
  );

  if (!hint) {
    return null;
  }

  return (
    <ResultHintLine data-testid='search-result-hint'>
      <strong>{hint.label}:</strong> {hint.before}
      <mark>{hint.match}</mark>
      {hint.after}
    </ResultHintLine>
  );
}

const ResultCard: React.FC<ResultCardProps> = ({
  subject,
  query,
  index,
  selected,
  onSelect,
}) => (
  <ResultRowWrapper data-index={index} onClick={onSelect} $selected={selected}>
    <ResourceRow subject={subject} clickable />
    <SearchResultHint subject={subject} query={query} />
  </ResultRowWrapper>
);

// ─── Shortcuts Overlay ────────────────────────────────────────────────────────

const ShortcutRow = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.5rem 1rem;
  border-bottom: 1px solid ${p => p.theme.colors.bg2};
  font-size: 0.875rem;

  &:last-child {
    border-bottom: none;
  }
`;

const ShortcutLabel = styled.span`
  color: ${p => p.theme.colors.text};
`;

const ShortcutKey = styled.kbd`
  background: ${p => p.theme.colors.bg1};
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: 0.25rem;
  padding: 0.15rem 0.4rem;
  font-size: 0.75rem;
  color: ${p => p.theme.colors.textLight};
  font-family: inherit;
`;

function ShortcutsOverlay(): JSX.Element {
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    const timer = setTimeout(() => inputRef.current?.focus(), 50);

    return () => clearTimeout(timer);
  }, []);

  const [query, setQuery] = useState('');

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      closeOverlay();
    }
  };

  // Rendered from the action registry so this overlay can't drift from
  // the actual bindings or the `/app/shortcuts` page.
  const shortcuts_list = listShortcutHelp();

  const search = query.trim().toLowerCase();
  const visibleShortcuts = shortcuts_list.filter(
    ({ shortcut, label }) =>
      label.toLowerCase().includes(search) ||
      displayShortcut(shortcut).toLowerCase().includes(search),
  );

  return (
    <>
      <OverlayInputWrapper>
        <span style={{ fontSize: '0.9rem', color: 'textLight' }}>
          Keyboard shortcuts
        </span>
        <OverlayInput
          ref={inputRef}
          onKeyDown={handleKeyDown}
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder='Filter shortcuts…'
          style={{ fontSize: '0.875rem' }}
        />
        <ShortcutHint onClick={closeOverlay}>esc</ShortcutHint>
      </OverlayInputWrapper>
      <ShortcutsList>
        {visibleShortcuts.map(({ id, shortcut, label }) => (
          <ShortcutRow key={id}>
            <ShortcutLabel>{label}</ShortcutLabel>
            <ShortcutKey>{displayShortcut(shortcut)}</ShortcutKey>
          </ShortcutRow>
        ))}
        {visibleShortcuts.length === 0 && (
          <NoShortcutsFound>No matching shortcuts</NoShortcutsFound>
        )}
      </ShortcutsList>
    </>
  );
}

/** Scrolls inside the fixed-height overlay panel instead of spilling out. */
const ShortcutsList = styled.div`
  flex: 1;
  min-height: 0;
  overflow-y: auto;
`;

const NoShortcutsFound = styled.div`
  padding: 1rem;
  color: ${p => p.theme.colors.textLight};
  font-size: 0.875rem;
`;

// ─── OverlayContainer ──────────────────────────────────────────────────────────

export function OverlayContainer(): JSX.Element | null {
  const [overlay, setOverlayState] = useState<OverlayType>(null);
  const [, setPreviewState] = useState({
    results: [] as string[],
    index: 0,
  });

  useEffect(() => subscribeOverlay(setOverlayState), []);

  useEffect(() => {
    const handler = (isOpen: boolean, results: string[], index: number) => {
      setPreviewState({ results, index });
    };

    previewListeners.add(handler);

    return () => {
      previewListeners.delete(handler);
    };
  }, []);

  useHotkeys(
    shortcuts.search,
    e => {
      e.preventDefault();
      setOverlay('search');
    },
    {},
    [],
  );

  useHotkeys(
    shortcuts.keyboardShortcuts,
    e => {
      e.preventDefault();
      setOverlay('shortcuts');
    },
    {},
    [],
  );

  useHotkeys(
    'escape',
    () => {
      closeOverlay();
    },
    {},
    [overlay],
  );

  if (overlay === null) {
    return null;
  }

  const previewSubject =
    overlay === 'search' && searchResults[searchSelectedIndex]
      ? searchResults[searchSelectedIndex]
      : null;

  return (
    <>
      <OverlayBackdrop onClick={closeOverlay} />
      <OverlayPanel onClick={e => e.stopPropagation()}>
        {overlay === 'search' && <SearchOverlay />}
        {overlay === 'shortcuts' && <ShortcutsOverlay />}
        {previewSubject && (
          <PreviewFloat>
            <CardPreview subject={previewSubject} />
          </PreviewFloat>
        )}
      </OverlayPanel>
    </>
  );
}

const ScopeChip = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.4rem 1rem;
  border-bottom: 1px solid ${p => p.theme.colors.bg2};
  font-size: 0.85rem;
  color: ${p => p.theme.colors.textLight};
`;

const ScopeClear = styled.button`
  border: none;
  background: none;
  cursor: pointer;
  color: inherit;
  font-size: 1rem;
  line-height: 1;
  padding: 0 0.25rem;
  border-radius: ${p => p.theme.radius};

  &:hover {
    background: ${p => p.theme.colors.bg1};
    color: ${p => p.theme.colors.text};
  }
`;
