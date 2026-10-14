import { useCustomContextItems } from '@components/ResourceContextMenu';
import { useCallback, useMemo, useEffect, useRef, useState } from 'react';
import styled from 'styled-components';
import {
  dataBrowser,
  useCanWrite,
  useStore,
  type Resource,
} from '@tomic/react';
import { Button } from '@components/Button';
import { Row, Column } from '@components/Row';
import { ResourceRow } from '@views/ResourceRow';
import Field from '@components/forms/Field';
import { FaPencil, FaPlus } from 'react-icons/fa6';
import { AIIcon } from '@components/AI/AIIcon';
import { CalculatedPageHeight } from '../../globalCssVars';
import { ResourceSelector } from '@components/forms/ResourceSelector';
import { useAISidebar, newContextItem } from '@components/AI/AISidebarContext';
import type { AIAtomicResourceMessageContext } from '@chunks/AI/types';
import { readWebsite, updateWebsite, type WebsiteConfig } from './websiteModel';
import {
  buildWebsiteArtifact,
  downloadWebsite,
  readWebsiteRelease,
  saveWebsiteRelease,
  selectedSubjects,
} from './websiteExport';
import type { WebsiteArtifact } from './renderWebsite';
import { WebsiteHosting } from './WebsiteHosting';
import { retryDelayMs } from '@helpers/retryBackoff';
import { WebsitePreview } from './WebsitePreview';
import { WebsiteInlinePreview } from './WebsiteInlinePreview';

export function WebsitePage({ resource }: { resource: Resource }) {
  const store = useStore();
  const drive = store.getDrive()!;
  const canWrite = useCanWrite(resource);
  const { askAI } = useAISidebar();
  const [config, setConfig] = useState<WebsiteConfig>();
  const [draft, setDraft] = useState<WebsiteArtifact>();
  const [release, setRelease] = useState<WebsiteArtifact>();
  const reportedReleaseError = useRef('');
  const [inlineArtifact, setInlineArtifact] = useState<WebsiteArtifact>();
  const [review, setReview] = useState<WebsiteArtifact>();
  const [pagePath, setPagePath] = useState('/');
  const [showRelease, setShowRelease] = useState(false);
  const [problem, setProblem] = useState('');
  const reportedProblem = useRef('');
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  /**
   * True while the draft is being rebuilt, which every remote edit starts and
   * which takes a second or two on a loaded machine. It shows the "Updating
   * preview…" toolbar, and it withholds the draft from publishing, which is
   * the one thing that must not go out a version behind.
   *
   * It deliberately does not disable the buttons that open the draft, because
   * a control that goes disabled and back under the pointer loses the click
   * that was already on its way: the browser drops a click whose target turned
   * disabled in between, silently. Opening a draft one rebuild old costs
   * nothing, since inline editing freezes a snapshot anyway and refreshes when
   * it ends.
   */
  const [refreshing, setRefreshing] = useState(true);
  const [document, setDocument] = useState<string>();
  const [addingContent, setAddingContent] = useState(false);

  useEffect(() => {
    let active = true;
    void readWebsiteRelease(store, drive, resource)
      .then(saved => {
        if (active) setRelease(saved);
      })
      .catch(cause => {
        if (active && reportedReleaseError.current !== String(cause)) {
          reportedReleaseError.current = String(cause);
          store.notifyError(
            new Error(
              'Could not load saved website version: ' + String(cause),
              { cause },
            ),
          );
        }
      });

    return () => {
      active = false;
    };
  }, [store, drive, resource]);

  useEffect(() => {
    let previous: string | undefined;
    let active = true;
    let attempts = 0;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let unsubscribe = () => {};

    const watch = async () => {
      try {
        const { property } = await readWebsite(store, drive, resource);

        if (!active) return;

        attempts = 0;
        previous = String(resource.get(property));
        unsubscribe = store.subscribe(resource.subject, () => {
          const next = String(resource.get(property));

          if (next !== previous) {
            previous = next;
            setRefresh(n => n + 1);
          }
        });
      } catch {
        if (!active) return;

        // The preview effect reports schema errors, so this one stays quiet.
        // It does have to ask again though: without this subscription an edit
        // to the website never rebuilds the preview, and one failed read used
        // to cost it for as long as the page stayed open.
        attempts += 1;
        retry = setTimeout(() => void watch(), retryDelayMs(attempts));
      }
    };

    void watch();

    return () => {
      active = false;
      clearTimeout(retry);
      unsubscribe();
    };
  }, [store, drive, resource]);

  useEffect(() => {
    let active = true;
    let attempts = 0;
    let retry: ReturnType<typeof setTimeout> | undefined;

    const build = async () => {
      try {
        const result = await readWebsite(store, drive, resource);

        if (!active) return;

        setConfig(result.config);
        const next = await buildWebsiteArtifact(
          store,
          resource.subject,
          result.config,
        );

        if (!active) return;

        attempts = 0;
        reportedProblem.current = '';
        setProblem('');
        setDraft(previous =>
          previous?.digest === next.digest &&
          JSON.stringify(previous.config) === JSON.stringify(next.config)
            ? previous
            : next,
        );
        setRefreshing(false);
      } catch (error) {
        if (!active) return;

        setRefreshing(false);
        const failure = new Error(
          `Website preview failed: ${error instanceof Error ? error.message : String(error)}`,
          { cause: error },
        );
        setProblem(failure.message);

        if (reportedProblem.current !== failure.message) {
          reportedProblem.current = failure.message;
          store.notifyError(failure);
        }

        // And ask again. A read that failed is not the same answer as a
        // website that cannot be built: `store.getResource` gives up after its
        // own 10s settle timeout, which a loaded machine reaches, and the page
        // then sat on "Publishing is unavailable" until someone noticed the
        // button. Nothing else was going to ask, either: the subscription that
        // bumps `refresh` is registered by the effect above, which needs the
        // same read to succeed. The ceiling keeps a genuinely unbuildable site
        // from polling the server for as long as its page is open, and the
        // manual Retry stays for the impatient.
        attempts += 1;
        retry = setTimeout(() => void build(), retryDelayMs(attempts));
      }
    };

    setRefreshing(true);
    setProblem('');
    void build();

    return () => {
      active = false;
      clearTimeout(retry);
    };
  }, [store, drive, resource, refresh]);
  const subjects = config ? JSON.stringify(selectedSubjects(config)) : '[]';
  // Inline editing shows a frozen snapshot, and every keystroke commits. Rebuilding
  // the whole draft on each one starves the editor, so defer until editing ends.
  const inlineEditing = !!inlineArtifact;
  const inlineEditingRef = useRef(inlineEditing);
  const pendingRefresh = useRef(false);
  useEffect(() => {
    inlineEditingRef.current = inlineEditing;

    if (!inlineEditing && pendingRefresh.current) {
      pendingRefresh.current = false;
      setRefresh(n => n + 1);
    }
  }, [inlineEditing]);
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    const unsubs = (JSON.parse(subjects) as string[]).map(subject =>
      store.subscribe(subject, () => {
        if (inlineEditingRef.current) {
          pendingRefresh.current = true;

          return;
        }

        clearTimeout(timer);
        timer = setTimeout(() => setRefresh(n => n + 1), 150);
      }),
    );

    return () => {
      clearTimeout(timer);
      unsubs.forEach(unsub => unsub());
    };
  }, [store, subjects]);

  const perform = useCallback(
    async (action: () => Promise<unknown>) => {
      setBusy(true);

      try {
        await action();
      } catch (error) {
        store.notifyError(
          error instanceof Error ? error : new Error(String(error)),
        );
      }

      setBusy(false);
    },
    [store],
  );

  const designWithAI = useCallback(
    () =>
      askAI({
        prompt:
          /* @wc-ignore */ 'Help me design this website. Read it with describe_website, ask what I want to change, then use update_website. Keep content in its existing Atomic documents and tables.',
        context: [
          newContextItem<AIAtomicResourceMessageContext>({
            type: 'atomic-resource',
            subject: resource.subject,
          }),
        ],
      }),
    [askAI, resource.subject],
  );

  const exportActions = useMemo(
    () => [
      {
        id: 'website-design',
        label: 'Design with AI',
        disabled: !canWrite,
        onClick: designWithAI,
      },
      {
        id: 'website-prepare',
        label: 'Prepare release',
        disabled: !draft || !canWrite || busy || !!problem,
        onClick: () => setReview(draft),
      },
      {
        id: 'website-show-release',
        label: showRelease ? 'Show draft' : 'Show release',
        disabled: !release,
        onClick: () => setShowRelease(value => !value),
      },
      {
        id: 'website-download',
        label: 'Download website',
        disabled: !release || busy,
        onClick: () => {
          if (release) void perform(() => downloadWebsite(release, store));
        },
      },
    ],
    [
      designWithAI,
      draft,
      canWrite,
      busy,
      problem,
      release,
      showRelease,
      perform,
      store,
    ],
  );
  useCustomContextItems(exportActions);

  const change = (next: WebsiteConfig) =>
    perform(async () => {
      await updateWebsite(store, drive, resource, next);
      setRefresh(n => n + 1);
    });
  const shown = review ?? (showRelease ? release : draft);
  const currentPage =
    config?.pages.find(page => page.path === pagePath) ?? config?.pages[0];
  const file = `${pagePath.slice(1)}index.html`;
  const html = shown?.files[file] ?? shown?.files['index.html'];

  return (
    <Workspace>
      <Header>
        <Title>
          <h1>{config?.title ?? resource.title}</h1>
        </Title>
        <Row>
          {!review && !showRelease && (
            <>
              <Button subtle disabled={!canWrite} onClick={designWithAI}>
                <AIIcon aria-hidden /> <span>AI edit</span>
              </Button>
              <Button
                subtle
                disabled={!draft || busy || !!problem}
                onClick={() =>
                  setInlineArtifact(inlineArtifact ? undefined : draft)
                }
              >
                <FaPencil aria-hidden />{' '}
                <span>{inlineArtifact ? 'Done editing' : 'Page edit'}</span>
              </Button>
            </>
          )}
          <WebsiteHosting
            key={resource.subject}
            project={resource.subject}
            draft={refreshing ? undefined : draft}
            draftError={problem}
            savedDigest={release?.digest}
            canWrite={!!canWrite}
            secondary={!!review}
            saveRelease={async artifact => {
              const saved = await saveWebsiteRelease(
                store,
                drive,
                resource,
                artifact,
              );
              setRelease(artifact);

              return saved;
            }}
          />
        </Row>
      </Header>
      {problem && (
        <div role='alert'>
          <p>{problem}</p>
          <p>
            Publishing is unavailable until the draft preview can be built.
            Check access to the selected content, then retry.
          </p>
          <Button
            subtle
            onClick={() => {
              reportedProblem.current = '';
              setRefresh(n => n + 1);
            }}
          >
            Retry preview
          </Button>
        </div>
      )}
      {review && (
        <Review aria-label='Review website release'>
          <h2>Review release</h2>
          <p>
            This freezes the pages shown below. It does not make your website
            public.
          </p>
          <ul>
            {review.config.pages.map(page => (
              <li key={page.path}>
                {page.title}: {page.documents.length} documents,{' '}
                {page.tables.reduce((n, table) => n + table.rows.length, 0)}{' '}
                selected rows
              </li>
            ))}
          </ul>
          <Row>
            <Button
              data-website-primary
              disabled={busy}
              onClick={() =>
                perform(async () => {
                  await saveWebsiteRelease(store, drive, resource, review);
                  setRelease(review);
                  setReview(undefined);
                  setShowRelease(true);
                })
              }
            >
              Create release
            </Button>
            <Button subtle onClick={() => setReview(undefined)}>
              Cancel
            </Button>
          </Row>
        </Review>
      )}
      <Layout>
        <Controls role='region' aria-label='Website content'>
          {config && (
            <Field label='Page' fieldId='website-page'>
              <select
                id='website-page'
                value={pagePath}
                onChange={event => setPagePath(event.target.value)}
              >
                {config.pages.map(page => (
                  <option key={page.path} value={page.path}>
                    {page.title}
                  </option>
                ))}
              </select>
            </Field>
          )}
          {currentPage?.documents.map(subject => (
            <ResourceRow key={subject} subject={subject} clickable />
          ))}
          {currentPage?.tables.map(table => (
            <ResourceRow key={table.table} subject={table.table} clickable />
          ))}
          {currentPage?.media?.map(media => (
            <ResourceRow
              key={media.subject}
              subject={media.subject}
              clickable
            />
          ))}
          {canWrite && (
            <>
              <Button
                subtle
                onClick={() => setAddingContent(true)}
                disabled={addingContent}
              >
                <FaPlus aria-hidden /> <span>Add content</span>
              </Button>
              {addingContent && (
                <Column>
                  <Field label='Add a document' fieldId='website-document'>
                    <ResourceSelector
                      id='website-document'
                      isA={dataBrowser.classes.documentV2}
                      value={document}
                      setSubject={setDocument}
                      hideCreateOption
                    />
                  </Field>
                  <Button
                    subtle
                    disabled={!document || !config || busy}
                    onClick={() => {
                      if (!document || !config || !currentPage) return;
                      void change({
                        ...config,
                        pages: config.pages.map(page =>
                          page.path === currentPage.path
                            ? {
                                ...page,
                                documents: [
                                  ...new Set([...page.documents, document]),
                                ],
                              }
                            : page,
                        ),
                      });
                      setDocument(undefined);
                      setAddingContent(false);
                    }}
                  >
                    Add to page
                  </Button>
                  <Button subtle onClick={() => setAddingContent(false)}>
                    Cancel
                  </Button>
                </Column>
              )}
            </>
          )}
        </Controls>
        <Preview>
          {(review || showRelease || (refreshing && draft)) && (
            <PreviewToolbar>
              <p>
                {review
                  ? 'Release review'
                  : showRelease
                    ? 'Frozen release'
                    : 'Updating preview…'}
              </p>
            </PreviewToolbar>
          )}
          {!review &&
          !showRelease &&
          inlineArtifact?.project === resource.subject ? (
            <WebsiteInlinePreview
              key={`${inlineArtifact.digest}:${pagePath}`}
              artifact={inlineArtifact}
              pagePath={pagePath}
            />
          ) : html && (showRelease || review) ? (
            <iframe title='Website preview' sandbox='' srcDoc={html} />
          ) : html ? (
            <WebsitePreview
              key={`${shown!.digest}:${pagePath}`}
              artifact={shown!}
              pagePath={pagePath}
              onNavigate={setPagePath}
            />
          ) : (
            <p>
              {problem
                ? 'Preview unavailable. Resolve the error above and retry.'
                : 'Preparing preview…'}
            </p>
          )}
        </Preview>
      </Layout>
    </Workspace>
  );
}

const Workspace = styled.div`
  /* Fill the page so the preview can take every spare pixel. */
  min-height: ${CalculatedPageHeight.var()};
  display: flex;
  flex-direction: column;
  padding: ${p => p.theme.size(3)} ${p => p.theme.size(3)}
    ${p => p.theme.size(2)};
  width: 100%;
  min-width: 0;
  box-sizing: border-box;
  h1 {
    margin: 0;
  }
  p {
    line-height: 1.5;
  }
`;
const Layout = styled.div`
  display: grid;
  grid-template-columns: 220px minmax(0, 1fr);
  gap: 1.5rem;
  flex: 1;
  min-height: 0;
  @media (max-width: 800px) {
    grid-template-columns: 1fr;
  }
`;
const Controls = styled(Column)`
  @media (max-width: 800px) {
    order: 2;
  }
  gap: 1rem;
  min-width: 0;
  font-size: 0.9rem;
  details {
    border-top: 1px solid ${p => p.theme.colors.bg2};
    padding-top: 1rem;
  }
  summary {
    cursor: pointer;
    font-weight: 600;
    margin-bottom: 1rem;
  }
  details > button {
    margin-top: 0.75rem;
  }
  h2 {
    font-size: 1rem;
    margin: 1rem 0 0;
  }
  select {
    width: 100%;
    padding: 0.6rem;
  }
`;
const Preview = styled.div`
  min-width: 0;
  display: flex;
  flex-direction: column;
  iframe {
    width: 100%;
    flex: 1;
    min-height: 60vh;
    display: block;
    border: 1px solid ${p => p.theme.colors.bg2};
    border-radius: 12px;
    background: white;
  }
`;
const Review = styled.section`
  padding: 1.5rem;
  margin: 1rem 0;
  border: 1px solid ${p => p.theme.colors.main};
  border-radius: 12px;
`;

const Header = styled.header`
  button,
  a {
    font: inherit;
    line-height: 1.25;
  }
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
  margin-bottom: 1.5rem;
  > div:last-child {
    flex-wrap: wrap;
  }
`;
const Title = styled.div`
  min-width: 0;
  flex: 1 1 260px;
  h1 {
    font-size: clamp(1.25rem, 2.3vw, 1.8rem);
    overflow-wrap: anywhere;
    line-height: 1.2;
  }
`;
const PreviewToolbar = styled.div`
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  min-height: 2.5rem;
  margin-bottom: 0.75rem;
  p {
    margin: 0;
    font-size: 0.85rem;
    opacity: 0.7;
  }
`;
