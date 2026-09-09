import {
  useResource,
  useStore,
  useServerSearch,
  core,
  dataBrowser,
  ai,
} from '@tomic/react';
import { useCallback, useState, type FormEvent, type JSX } from 'react';
import { styled } from 'styled-components';
import { FaArrowUp, FaGlobe, FaMagnifyingGlass } from 'react-icons/fa6';
import toast from 'react-hot-toast';
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
import { ApplyTemplateDialog } from '../../components/Template/ApplyTemplateDialog';
import type {
  Template,
  TemplateDescriptor,
} from '../../components/Template/template';
import { creationAssistantAsk } from './creationAssistant';
import {
  BASIC_CREATIONS,
  CREATION_TABLE_TEMPLATES,
  CREATION_PAGE_TEMPLATES,
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
  const { drive } = useSettings();
  const destination = parentSubject || parent || drive;
  const parentResource = useResource(destination);
  const store = useStore();
  const navigate = useNavigateWithTransition();
  const showNewResourceUI = useNewResourceUI();
  const { askAI } = useAISidebar();
  const { enableAI, setEnableAI } = useAISettings();
  const [query, setQuery] = useState('');
  const [prompt, setPrompt] = useState('');
  const [template, setTemplate] = useState<Template>();
  const [templateOpen, setTemplateOpen] = useState(false);
  const [loadingTemplate, setLoadingTemplate] = useState('');
  const [templateError, setTemplateError] = useState('');
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
  const basic = BASIC_CREATIONS.filter(
    item =>
      (enableAI || item.subject !== ai.classes.aiChat) &&
      matchesCreationSearch(query, item.title, item.description, 'blank'),
  );
  const tables = CREATION_TABLE_TEMPLATES.filter(item =>
    matchesCreationSearch(
      query,
      item.title,
      item.description,
      'table template',
      ...(item.spec?.views ?? []).map(v => v.kind),
    ),
  );
  const pages = CREATION_PAGE_TEMPLATES.filter(item =>
    matchesCreationSearch(query, item.title, item.description, 'template'),
  );
  const custom = customClasses.filter(
    subject => !BASIC_CREATIONS.some(item => item.subject === subject),
  );
  const noMatches =
    basic.length + tables.length + pages.length + custom.length === 0 &&
    !loading;

  const onUploadComplete = useCallback(
    (files: string[]) => {
      toast.success(`Uploaded ${files.length} files.`);
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

  const ask = (event: FormEvent) => {
    event.preventDefault();
    if (!prompt.trim()) return;
    if (!enableAI) setEnableAI(true);
    askAI(creationAssistantAsk(prompt, destination));
  };

  return (
    <CatalogContainer>
      <Column gap='1.75rem'>
        <Column gap='0.4rem'>
          <h1>Create something new</h1>
          <Destination>
            <span>In</span>
            <ResourceInline subject={destination} />
          </Destination>
        </Column>
        <Column gap='0.5rem'>
          <label htmlFor='creation-prompt'>
            Describe your idea and build it with the Atomic assistant.
          </label>
          <Composer onSubmit={ask}>
            <PromptInput
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
        </Column>
        <Column gap='0.75rem'>
          <SearchInput hasPrefix>
            <FaMagnifyingGlass aria-hidden />
            <InputStyled
              type='search'
              aria-label='Search templates and resource types'
              placeholder='Search templates and resource types…'
              value={query}
              onChange={e => setQuery(e.target.value)}
            />
            {query && (
              <Button subtle onClick={() => setQuery('')}>
                Clear
              </Button>
            )}
          </SearchInput>
          {noMatches && (
            <p role='status'>
              No matches. Try another search or describe your idea to the
              assistant above.
            </p>
          )}
        </Column>
        {basic.length > 0 && (
          <section aria-label='Start blank'>
            <SectionHeading>Start blank</SectionHeading>
            <BasicGrid>
              {basic.map(item => {
                const Icon = getIconForClass(item.subject);

                return (
                  <BasicChoice
                    key={item.subject}
                    subtle
                    title={item.description}
                    onClick={() => showNewResourceUI(item.subject, destination)}
                  >
                    <Icon aria-hidden />
                    {item.title}
                  </BasicChoice>
                );
              })}
            </BasicGrid>
          </section>
        )}
        {(tables.length > 0 || pages.length > 0) && (
          <section aria-label='Templates'>
            <SectionHeading>Start with a template</SectionHeading>
            <TemplateGrid>
              {tables.map(item => (
                <TemplateChoice
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
                  <Kind>Table template</Kind>
                </TemplateChoice>
              ))}
              {pages.map(item => (
                <TemplateChoice
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
              {custom.map(subject => (
                <CustomChoice
                  key={subject}
                  subject={subject}
                  onClick={() => showNewResourceUI(subject, destination)}
                />
              ))}
            </BasicGrid>
          </section>
        )}
        {error && (
          <p role='alert'>
            Your resource types could not be loaded. Templates above are still
            available.
          </p>
        )}
        <details>
          <summary>Choose a class by URL</summary>
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
        <CompactUpload
          parentResource={parentResource}
          onFilesUploaded={onUploadComplete}
        />
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

function CustomChoice({
  subject,
  onClick,
}: {
  subject: string;
  onClick: () => void;
}) {
  const resource = useResource(subject);
  const Icon = getIconForClass(subject);

  return (
    <BasicChoice subtle onClick={onClick}>
      <Icon aria-hidden />
      {resource.title}
    </BasicChoice>
  );
}

const CatalogContainer = styled(ContainerWide)`
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
const SearchInput = styled(InputWrapper)`
  min-height: 2.75rem;
  width: 100%;
  input {
    min-width: 0;
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
