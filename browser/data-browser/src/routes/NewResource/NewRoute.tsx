import {
  useResource,
  useStore,
  useServerSearch,
  core,
  dataBrowser,
  ai,
} from '@tomic/react';
import { useCallback, useRef, useState, type FormEvent, type JSX } from 'react';
import { styled } from 'styled-components';
import {
  FaArrowUp,
  FaGlobe,
  FaMagnifyingGlass,
  FaXmark,
} from 'react-icons/fa6';
import { createRoute } from '@tanstack/react-router';
import { appRoute } from '../RootRoutes';
import { pathNames } from '../paths';
import { ContainerNarrow, ContainerWide } from '../../components/Containers';
import { Main } from '../../components/Main';
import { Button } from '../../components/Button';
import { Column, Row } from '../../components/Row';
import {
  InputStyled,
  InputWrapper,
  TextAreaStyled,
} from '../../components/forms/InputStyles';
import { ResourceSelector } from '../../components/forms/ResourceSelector';
import { FileDropzoneInput } from '../../components/forms/FileDropzone/FileDropzoneInput';
import { NewFormFullPage } from '../../components/forms/NewForm/NewFormPage';
import { useNewResourceUI } from '../../components/forms/NewForm/useNewResourceUI';
import { useSettings } from '../../helpers/AppSettings';
import { ResourceInline } from '../../views/ResourceInline';
import { constructOpenURL } from '../../helpers/navigation';
import { getIconForClass } from '../../helpers/iconMap';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { useAISidebar } from '../../components/AI/AISidebarContext';
import { useAISettings } from '../../components/AI/AISettingsContext';
import { useMarkNewActionDiscovered } from '../../hooks/useNewActionDiscovered';
import { ApplyTemplateDialog } from '../../components/Template/ApplyTemplateDialog';
import type {
  Template,
  TemplateDescriptor,
} from '../../components/Template/template';
import { creationAssistantAsk } from './creationAssistant';
import {
  AI_BUILD_SUGGESTIONS,
  BASIC_CREATIONS,
  DRIVE_CREATIONS,
  CREATION_TABLE_TEMPLATES,
  CREATION_PAGE_TEMPLATES,
  isUntouchedSuggestion,
  matchesCreationSearch,
} from './creationCatalog';

export interface NewRouteSearchParams {
  classSubject: string | undefined;
  parent: string | undefined;
  parentSubject: string | undefined;
  newSubject: string | undefined;
}

export const NewRoute = createRoute({
  path: pathNames.new,
  component: () => <NewRoutePage />,
  getParentRoute: () => appRoute,
  validateSearch: (search: Record<string, unknown>): NewRouteSearchParams => ({
    classSubject: (search.classSubject as string) ?? undefined,
    parent: (search.parent as string) ?? undefined,
    parentSubject: (search.parentSubject as string) ?? undefined,
    newSubject: (search.newSubject as string) ?? undefined,
  }),
});

/** A shared entry point for templates, basic resources and assistant-led creation. */
function NewRoutePage(): JSX.Element {
  const { classSubject } = NewRoute.useSearch();

  return (
    <Main>
      {classSubject ? (
        <ContainerNarrow>
          <NewFormFullPage classSubject={classSubject} />
        </ContainerNarrow>
      ) : (
        <NewResourceSelector />
      )}
    </Main>
  );
}

function NewResourceSelector() {
  const { parentSubject, parent } = NewRoute.useSearch();
  const { drive, hideTemplates } = useSettings();
  const destination = parentSubject || parent || drive;
  const parentResource = useResource(destination);
  const store = useStore();
  const navigate = useNavigateWithTransition();
  const showNewResourceUI = useNewResourceUI();
  const { askAI } = useAISidebar();
  const { enableAI } = useAISettings();
  const catalogRef = useRef<HTMLDivElement>(null);
  useMarkNewActionDiscovered();
  const [selectedIndex, setSelectedIndex] = useState(0);
  const searchRef = useRef<HTMLInputElement>(null);
  const promptRef = useRef<HTMLTextAreaElement>(null);
  const [query, setQuery] = useState('');
  const [prompt, setPrompt] = useState('');
  const [template, setTemplate] = useState<Template>();
  const [templateOpen, setTemplateOpen] = useState(false);
  const [loadingTemplate, setLoadingTemplate] = useState('');
  const [templateError, setTemplateError] = useState('');
  const [creating, setCreating] = useState(false);
  const {
    results: customClasses,
    loading,
    error,
  } = useServerSearch(query, {
    filters: { [core.properties.isA]: core.classes.class },
    parents: [drive],
    allowEmptyQuery: true,
    limit: 100,
  });
  const searching = query.trim().length > 0;
  const basic = [...BASIC_CREATIONS, ...DRIVE_CREATIONS].filter(
    item =>
      (searching || !('searchOnly' in item)) &&
      (enableAI ||
        !('subject' in item) ||
        item.subject !== ai.classes.aiChat) &&
      matchesCreationSearch(query, item.title, item.description, 'blank'),
  );
  const tables = (hideTemplates ? [] : CREATION_TABLE_TEMPLATES).filter(item =>
    matchesCreationSearch(
      query,
      item.title,
      item.description,
      'table template',
      ...(item.spec?.views ?? []).map(v => v.kind),
    ),
  );
  const pages = (hideTemplates ? [] : CREATION_PAGE_TEMPLATES).filter(item =>
    matchesCreationSearch(query, item.title, item.description, 'template'),
  );
  const custom = customClasses.filter(
    subject =>
      !BASIC_CREATIONS.some(item => item.subject === subject) &&
      !DRIVE_CREATIONS.some(
        item =>
          item.shortname ===
          store.getResourceLoading(subject).get(core.properties.shortname),
      ),
  );
  const showUpload = matchesCreationSearch(query, 'files upload');
  const noMatches =
    !showUpload &&
    basic.length + tables.length + pages.length + custom.length === 0 &&
    !loading;

  const onUploadComplete = useCallback(
    (files: string[]) => {
      navigate(constructOpenURL(files.length === 1 ? files[0] : destination));
    },
    [destination, navigate],
  );

  const openTemplate = async (descriptor: TemplateDescriptor) => {
    setLoadingTemplate(descriptor.id);
    setTemplateError('');

    try {
      const load = await descriptor.load();
      setTemplate(load({ driveURL: drive, serverURL: store.getServerUrl() }));
      setTemplateOpen(true);
    } catch (e) {
      setTemplateError(String(e));
    } finally {
      setLoadingTemplate('');
    }
  };

  /**
   * Hands a half-written request to the composer rather than sending it.
   *
   * Focus moves with it, caret at the end, so the next thing the user does is
   * finish the sentence. Sending it as it stands would only make the assistant
   * ask what they wanted built.
   */
  const applySuggestion = (seed: string) => {
    setPrompt(seed);
    const input = promptRef.current;

    if (!input) return;

    input.focus();
    input.setSelectionRange(seed.length, seed.length);
  };

  const ask = (event: FormEvent) => {
    event.preventDefault();
    if (!prompt.trim()) return;

    askAI(creationAssistantAsk(prompt, destination));
  };

  const openCreation = async (item: (typeof basic)[number]) => {
    if ('subject' in item) {
      showNewResourceUI(item.subject, destination);

      return;
    }

    if (creating) return;
    setCreating(true);

    try {
      const { createDriveResource } = await import('./createDriveResource');
      const subject = await createDriveResource(
        item.shortname,
        store,
        drive,
        destination,
      );
      navigate(constructOpenURL(subject));
    } catch (creationError) {
      store.notifyError(creationError);
    } finally {
      setCreating(false);
    }
  };

  return (
    <CatalogContainer ref={catalogRef}>
      <Column gap='1.75rem'>
        <Column gap='0.4rem'>
          <h1>Create something new</h1>
          <Destination>
            <span>In</span>
            <ResourceInline subject={destination} />
          </Destination>
        </Column>
        <Column gap='0.75rem'>
          <SearchInput hasPrefix>
            <FaMagnifyingGlass aria-hidden />
            <InputStyled
              ref={searchRef}
              autoFocus
              type='search'
              aria-label='Search templates and resource types'
              placeholder='Search templates and resource types…'
              value={query}
              onChange={e => {
                setQuery(e.target.value);
                setSelectedIndex(0);
              }}
              onKeyDown={e => {
                if (e.nativeEvent.isComposing) return;
                const results = Array.from(
                  catalogRef.current?.querySelectorAll<HTMLButtonElement>(
                    '[data-creation-result]',
                  ) ?? [],
                );
                if (!results.length) return;
                const current = Math.min(selectedIndex, results.length - 1);

                if (
                  /* @wc-ignore */
                  ['ArrowDown', 'ArrowUp', 'ArrowLeft', 'ArrowRight'].includes(
                    e.key,
                  )
                ) {
                  e.preventDefault();
                  const delta =
                    /* @wc-ignore */
                    e.key === 'ArrowDown' || e.key === 'ArrowRight' ? 1 : -1;
                  const next =
                    (current + delta + results.length) % results.length;
                  setSelectedIndex(next);
                  results[next].scrollIntoView({ block: 'nearest' });
                } else if (e.key === 'Enter') {
                  e.preventDefault();
                  results[current].click();
                }
              }}
            />
            {searching && enableAI && (
              <Button
                subtle
                onClick={() => askAI(creationAssistantAsk(query, destination))}
              >
                Ask AI
              </Button>
            )}
            {query && (
              <ClearSearch
                aria-label='Clear search'
                title='Clear search'
                onClick={() => {
                  setQuery('');
                  setSelectedIndex(0);
                  searchRef.current?.focus();
                }}
              >
                <FaXmark aria-hidden />
              </ClearSearch>
            )}
          </SearchInput>
          {noMatches && (
            <p role='status'>
              {enableAI ? (
                <>No matches. Try another search or ask AI to build it.</>
              ) : (
                <>No matches. Try another search.</>
              )}
            </p>
          )}
        </Column>
        {basic.length > 0 && (
          <section aria-label='Start blank'>
            <SectionHeading>Start blank</SectionHeading>
            <BasicGrid>
              {basic.map((item, index) => {
                const subject = 'subject' in item ? item.subject : undefined;
                const shortname =
                  'shortname' in item ? item.shortname : undefined;
                const Icon = getIconForClass(subject, undefined, shortname);

                return (
                  <BasicChoice
                    data-creation-result
                    data-selected={selectedIndex === index}
                    key={subject ?? shortname}
                    subtle
                    title={item.description}
                    disabled={creating}
                    onClick={() => void openCreation(item)}
                  >
                    <Icon aria-hidden />
                    {item.title}
                  </BasicChoice>
                );
              })}
            </BasicGrid>
          </section>
        )}
        {!searching && enableAI && (
          <Column gap='0.5rem'>
            <SectionHeading>Build with AI</SectionHeading>
            <Composer onSubmit={ask}>
              <PromptInput
                ref={promptRef}
                id='creation-prompt'
                aria-label='Describe what you want to create'
                rows={2}
                placeholder='A project tracker with tasks, deadlines and a kanban board…'
                value={prompt}
                onChange={e => setPrompt(e.target.value)}
                onKeyDown={e => {
                  if (
                    e.key === 'Enter' &&
                    !e.shiftKey &&
                    !e.nativeEvent.isComposing
                  ) {
                    e.preventDefault();
                    e.currentTarget.form?.requestSubmit();
                  }
                }}
              />
              <SendButton
                type='submit'
                disabled={!prompt.trim()}
                aria-label='Create with assistant'
                title='Create with assistant'
              >
                <FaArrowUp aria-hidden />
              </SendButton>
            </Composer>
            {isUntouchedSuggestion(prompt) && (
              <SuggestionRow
                role='group'
                aria-label='What the assistant can build'
              >
                {AI_BUILD_SUGGESTIONS.map(item => {
                  const Icon = getIconForClass(
                    item.subject,
                    undefined,
                    item.shortname,
                  );

                  return (
                    <Suggestion
                      key={item.id}
                      subtle
                      type='button'
                      aria-pressed={prompt === item.seed}
                      onClick={() => applySuggestion(item.seed)}
                    >
                      <Icon aria-hidden />
                      {item.title}
                    </Suggestion>
                  );
                })}
              </SuggestionRow>
            )}
          </Column>
        )}
        {showUpload && (
          <div>
            <CompactUpload
              parentResource={parentResource}
              onFilesUploaded={onUploadComplete}
            />
          </div>
        )}
        {(tables.length > 0 || pages.length > 0) && (
          <section aria-label='Templates'>
            <TemplateSectionHeading />
            <TemplateGrid>
              {tables.map((item, index) => (
                <TemplateChoice
                  data-creation-result
                  data-selected={selectedIndex === basic.length + index}
                  key={item.id}
                  subtle
                  aria-label={`Use ${item.title} template`}
                  onClick={() =>
                    showNewResourceUI(dataBrowser.classes.table, destination, {
                      initialTemplateId: item.id,
                    })
                  }
                >
                  <CardHeading>
                    <item.icon aria-hidden />
                    <strong>{item.title}</strong>
                  </CardHeading>
                  <CardDescription>{item.description}</CardDescription>
                </TemplateChoice>
              ))}
              {pages.map((item, index) => (
                <TemplateChoice
                  data-creation-result
                  data-selected={
                    selectedIndex === basic.length + tables.length + index
                  }
                  key={item.id}
                  subtle
                  aria-label={`Use ${item.title} template`}
                  data-testid='template-button'
                  disabled={!!loadingTemplate}
                  onClick={() => void openTemplate(item)}
                >
                  <CardHeading>
                    <FaGlobe aria-hidden />
                    <strong>{item.title}</strong>
                  </CardHeading>
                  <CardDescription>{item.description}</CardDescription>
                  <Kind>
                    {loadingTemplate === item.id
                      ? 'Loading…'
                      : 'Website template'}
                  </Kind>
                </TemplateChoice>
              ))}
            </TemplateGrid>
            {templateError && <p role='alert'>{templateError}</p>}
          </section>
        )}
        {custom.length > 0 && (
          <section aria-label='Your resource types'>
            <SectionHeading>Your resource types</SectionHeading>
            <BasicGrid>
              {custom.map((subject, index) => (
                <CustomChoice
                  key={subject}
                  selected={
                    selectedIndex ===
                    basic.length + tables.length + pages.length + index
                  }
                  subject={subject}
                  onClick={() => showNewResourceUI(subject, destination)}
                />
              ))}
            </BasicGrid>
          </section>
        )}
        {error && <p role='alert'>Your resource types could not be loaded.</p>}
        {!searching && (
          <details>
            <ChooseClassSummary />
            <Advanced>
              <ResourceSelector
                hideCreateOption
                setSubject={subject => {
                  if (subject) showNewResourceUI(subject, destination);
                }}
                isA={core.classes.class}
              />
            </Advanced>
          </details>
        )}
        <ApplyTemplateDialog
          template={template}
          parent={destination}
          open={templateOpen}
          bindOpen={setTemplateOpen}
        />
      </Column>
    </CatalogContainer>
  );
}

function ChooseClassSummary() {
  return <summary>Choose a class by URL</summary>;
}

function TemplateSectionHeading() {
  return <SectionHeading>Start with a template</SectionHeading>;
}

function CustomChoice({
  selected,
  subject,
  onClick,
}: {
  selected: boolean;
  subject: string;
  onClick: () => void;
}) {
  const resource = useResource(subject);
  const Icon = getIconForClass(subject);

  return (
    <BasicChoice
      data-creation-result
      data-selected={selected}
      subtle
      onClick={onClick}
    >
      <Icon aria-hidden />
      {resource.title}
    </BasicChoice>
  );
}

const CatalogContainer = styled(ContainerWide)`
  [data-creation-result][data-selected='true'] {
    outline: 2px solid ${p => p.theme.colors.main};
    outline-offset: 2px;
  }
  max-width: 72rem;
  padding-top: 2rem;
  h1 {
    margin: 0;
  }
`;
const Destination = styled(Row)`
  color: ${p => p.theme.colors.textLight};
  gap: 0.45rem;
`;
const Composer = styled.form`
  display: flex;
  align-items: center;
  gap: 0.75rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  padding: 0.6rem 0.75rem;
  background: ${p => p.theme.colors.bg};
  &:focus-within {
    border-color: ${p => p.theme.colors.main};
  }
`;
const PromptInput = styled(TextAreaStyled)`
  flex: 1;
  min-width: 0;
  resize: none;
  padding: 0.3rem 0;
  min-height: 2.75rem;
  line-height: 1.4;
`;
const SendButton = styled(Button)`
  flex-shrink: 0;
  width: 2.25rem;
  height: 2.25rem;
  border-radius: 50%;
  padding: 0;
  justify-content: center;
`;
const ClearSearch = styled.button`
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 2rem;
  height: 2rem;
  padding: 0;
  border: 0;
  border-radius: ${p => p.theme.radius};
  background: transparent;
  color: ${p => p.theme.colors.textLight};
  cursor: pointer;
  &:hover {
    color: ${p => p.theme.colors.main};
  }
  &:focus-visible {
    outline: 2px solid ${p => p.theme.colors.main};
  }
`;
const SearchInput = styled(InputWrapper)`
  box-sizing: border-box;
  padding-block: 0.25rem;
  padding-inline-end: 0.4rem;
  gap: 0.35rem;
  > button {
    flex-shrink: 0;
    margin: 0;
    align-self: center;
  }
  > svg {
    flex-shrink: 0;
  }
  min-height: 2.75rem;
  width: 100%;
  input {
    min-width: 0;
    &::-webkit-search-cancel-button {
      -webkit-appearance: none;
      appearance: none;
    }
  }
`;
const SectionHeading = styled.h2`
  font-size: 1.15rem;
  margin: 0 0 0.85rem;
`;
const BasicGrid = styled.div`
  display: flex;
  flex-wrap: wrap;
  gap: 0.6rem;
`;
const BasicChoice = styled(Button)`
  justify-content: flex-start;
  padding: 0.65rem 0.85rem;
  gap: 0.55rem;
  svg {
    color: ${p => p.theme.colors.textLight};
  }
`;
/**
 * The same button as the blank ones, wearing a rainbow border.
 *
 * Same shape on purpose: these make the same kind of thing, they just ask the
 * assistant to fill it in. The border is the only difference, and it is kept
 * faint at rest so a row of four does not outshout the page.
 */
const SuggestionRow = styled(BasicGrid)``;
const Suggestion = styled(BasicChoice)`
  --button-border-color: transparent;
  --button-border-color-hover: transparent;
  --button-text-color: ${p => p.theme.colors.text};
  --button-text-color-hover: ${p => p.theme.colors.text};
  background-image:
    linear-gradient(var(--button-bg-color), var(--button-bg-color)),
    linear-gradient(
      100deg,
      rgb(255 138 76 / 45%),
      rgb(248 87 166 / 45%) 30%,
      rgb(123 92 255 / 45%) 55%,
      rgb(59 178 246 / 45%) 80%,
      rgb(47 212 167 / 45%)
    );
  background-origin: border-box;
  background-clip: padding-box, border-box;
  &:hover:not([disabled]),
  &:focus-visible:not([disabled]),
  &[aria-pressed='true'] {
    background-image:
      linear-gradient(var(--button-bg-color), var(--button-bg-color)),
      linear-gradient(
        100deg,
        #ff8a4c,
        #f857a6 30%,
        #7b5cff 55%,
        #3bb2f6 80%,
        #2fd4a7
      );
  }
`;
const TemplateGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(min(100%, 15rem), 1fr));
  gap: 0.85rem;
`;
const TemplateChoice = styled(Button)`
  display: flex;
  flex-direction: column;
  align-items: stretch;
  justify-content: flex-start;
  gap: 0.65rem;
  padding: 1rem;
  text-align: start;
  white-space: normal;
  height: 100%;
`;
const CardHeading = styled.span`
  display: flex;
  align-items: center;
  gap: 0.7rem;
  color: ${p => p.theme.colors.text};
  svg {
    flex-shrink: 0;
    font-size: 1.3rem;
    color: ${p => p.theme.colors.main};
  }
`;
const CardDescription = styled.span`
  font-weight: normal;
  color: ${p => p.theme.colors.textLight};
  line-height: 1.5;
  font-size: 0.9rem;
`;
const Kind = styled.span`
  font-size: 0.75rem;
  color: ${p => p.theme.colors.textLight};
  font-weight: normal;
  margin-top: auto;
  padding-top: 0.25rem;
`;
const Advanced = styled.div`
  padding-top: 1rem;
`;
const CompactUpload = styled(FileDropzoneInput)`
  min-height: 5rem;
  font-size: 1rem;
`;
