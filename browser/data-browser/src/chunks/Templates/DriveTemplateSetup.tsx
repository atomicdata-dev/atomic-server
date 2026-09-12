import { getIconForClass } from '../../helpers/iconMap';
import { useState, useRef, lazy, Suspense } from 'react';
import { styled } from 'styled-components';
import { dataBrowser, useStore, type Resource } from '@tomic/react';
import { SIDEBAR_TOGGLE_WIDTH } from '../../components/SideBar';
import { Card } from '../../components/Card';
import { Button } from '../../components/Button';
import { Column, Row } from '../../components/Row';
import Field from '../../components/forms/Field';
import { InputStyled, InputWrapper } from '../../components/forms/InputStyles';
import { Checkbox } from '../../components/forms/Checkbox';
import { ErrorBlock } from '../../components/ErrorLook';
import { useSettings } from '../../helpers/AppSettings';
import { getManagedPortalUrl } from '../../helpers/managed/cloudSync';
import { constructOpenURL } from '../../helpers/navigation';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { TEMPLATE_CATALOG } from './catalog';
import { planTemplate, type TemplateDefinition } from './model';
import { instantiateTemplate, startTemplateDemo } from './instantiate';
import { readTemplateDemo, TEMPLATE_DEMO_KEY } from './demoSession';
import { keepTemplateDemo } from './keepTemplateDemo';
const TemplateChat = lazy(() => import('./TemplateChat'));

export function DriveTemplateSetup({
  onCreated,
  onPreview,
}: {
  onCreated: (resource: Resource) => void;
  onPreview?: () => void;
}) {
  const store = useStore();
  const navigate = useNavigateWithTransition();
  const { setDrive, setSideBarLocked } = useSettings();
  const initial = new URLSearchParams(window.location.search).get('template');
  const [selected, setSelected] = useState<TemplateDefinition | undefined>(() =>
    TEMPLATE_CATALOG.find(t => t.id === initial),
  );
  const [naming, setNaming] = useState(
    !!initial || new URLSearchParams(window.location.search).has('blank'),
  );
  const [name, setName] = useState(() => selected?.title ?? 'My drive');
  const [examples, setExamples] = useState(false);
  const [keepEdits, setKeepEdits] = useState(false);
  const demo = readTemplateDemo();
  const matchingDemo = demo?.template === selected?.id ? demo : undefined;
  const [busy, setBusy] = useState(false);
  const [preparingTemplate, setPreparingTemplate] = useState<string>();
  const busyRef = useRef(false);
  const [error, setError] = useState<Error>();
  const [partial, setPartial] = useState<Resource>();
  const plan = selected
    ? planTemplate(selected, TEMPLATE_CATALOG, examples)
    : undefined;

  function chooseBlank() {
    if (busy) return;
    setSelected(undefined);
    setName('My drive');
    setNaming(true);
  }

  async function run(action: () => Promise<void>) {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    setError(undefined);

    try {
      await action();
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    } finally {
      busyRef.current = false;
      setBusy(false);
      setPreparingTemplate(undefined);
    }
  }

  async function preview(template: TemplateDefinition) {
    await run(async () => {
      setPreparingTemplate(template.id);

      if (template.id === 'interactive-demo') {
        onPreview?.();
        navigate('/app/demo');

        return;
      }

      const subject = await startTemplateDemo(
        store,
        planTemplate(template, TEMPLATE_CATALOG, true),
      );
      setDrive(store.getDrive()!);
      if (window.innerWidth < SIDEBAR_TOGGLE_WIDTH) setSideBarLocked(true);
      onPreview?.();
      navigate(constructOpenURL(subject));
    });
  }

  async function create() {
    if (!name.trim() || partial) return;
    await run(async () => {
      if (keepEdits && matchingDemo) {
        const resource = await keepTemplateDemo(
          store,
          matchingDemo,
          name.trim(),
        );
        await store.notifyResourceManuallyCreated(resource);
        onCreated(resource);

        return;
      }

      const resource = await store.createDrive(name.trim(), {
        personal: false,
        localOnly: !!getManagedPortalUrl(),
      });
      setPartial(resource);
      if (plan)
        await instantiateTemplate(store, plan, {
          parent: resource.subject,
          drive: resource.subject,
        });
      if (plan && window.innerWidth < SIDEBAR_TOGGLE_WIDTH)
        setSideBarLocked(true);

      if (matchingDemo) {
        const { cleanupDemoDrive } = await import('../Demo/startDemo');
        await cleanupDemoDrive(store, matchingDemo.drive);
        localStorage.removeItem(TEMPLATE_DEMO_KEY);
      }

      store.notifyResourceManuallyCreated(resource);
      onCreated(resource);
    });
  }

  return (
    <Column gap='1.5rem'>
      {error && (
        <>
          <ErrorBlock error={error} />
          {partial && (
            <>
              <p>
                The drive was created, but setup did not finish. Open it to
                inspect what was saved.
              </p>
              <Button onClick={() => onCreated(partial)}>Open drive</Button>
            </>
          )}
        </>
      )}
      {naming ? (
        <>
          <Button
            subtle
            disabled={busy || !!partial}
            onClick={() => setNaming(false)}
          >
            Back to templates
          </Button>
          <h1>Give your space a name</h1>
          <form
            onSubmit={e => {
              e.preventDefault();
              void create();
            }}
          >
            <Column>
              <Field label='Drive name' fieldId='new-drive-name' required>
                <InputWrapper>
                  <InputStyled
                    id='new-drive-name'
                    value={name}
                    onChange={e => setName(e.target.value)}
                    autoFocus
                    onFocus={event => event.currentTarget.select()}
                    disabled={busy || !!partial}
                  />
                </InputWrapper>
              </Field>
              {selected && (
                <Card>
                  <Column>
                    <TemplatePreview template={selected} />
                    {matchingDemo && (
                      <label htmlFor='template-keep-edits'>
                        <Row>
                          <Checkbox
                            id='template-keep-edits'
                            checked={keepEdits}
                            onChange={setKeepEdits}
                            disabled={busy || !!partial}
                          />
                          Keep demo content and my edits
                        </Row>
                      </label>
                    )}
                    {!keepEdits && (
                      <label htmlFor='template-examples'>
                        <Row>
                          <Checkbox
                            id='template-examples'
                            checked={examples}
                            onChange={setExamples}
                            disabled={busy || !!partial}
                          />
                          Include example content
                        </Row>
                      </label>
                    )}
                  </Column>
                </Card>
              )}
              <Button
                type='submit'
                disabled={busy || !!partial || !name.trim()}
              >
                {busy ? 'Creating…' : 'Create drive'}
              </Button>
            </Column>
          </form>
        </>
      ) : (
        <>
          <p>
            Start with a template,{' '}
            <a
              href='/app/new-drive?blank=1'
              onClick={event => {
                event.preventDefault();
                chooseBlank();
              }}
            >
              create a blank drive
            </a>
            , or describe a space of your own.
          </p>
          <Gallery>
            {TEMPLATE_CATALOG.filter(t =>
              t.entryPoints.includes('workspace'),
            ).map(template => (
              <Card key={template.id}>
                <Column>
                  <TemplatePreview template={template} />
                  <p>{template.description}</p>
                  <Button
                    subtle
                    disabled={busy}
                    onClick={() => void preview(template)}
                  >
                    {preparingTemplate === template.id
                      ? 'Preparing…'
                      : 'Preview template'}
                  </Button>
                </Column>
              </Card>
            ))}
          </Gallery>
          <Suspense fallback={<p>Loading AI setup…</p>}>
            <TemplateChat
              onProposal={template => {
                setSelected(template);
                setName(template.title);
                setNaming(true);
              }}
            />
          </Suspense>
          <Row style={{ flexWrap: 'wrap', justifyContent: 'flex-start' }}>
            <span>Prefer a fresh start?</span>
            <Button
              style={{ whiteSpace: 'nowrap' }}
              disabled={busy}
              onClick={chooseBlank}
            >
              Create a blank drive
            </Button>
          </Row>
        </>
      )}
    </Column>
  );
}

const TableIcon = getIconForClass(dataBrowser.classes.table);
const DocumentIcon = getIconForClass(dataBrowser.classes.documentV2);
const ChatIcon = getIconForClass(dataBrowser.classes.chatroom);

/** Shared by the gallery and the selected-template summary. */
function TemplatePreview({ template }: { template: TemplateDefinition }) {
  return (
    <>
      <strong>
        {template.icon} {template.title}
      </strong>
      <SidebarPreview aria-label={`${template.title} contents`}>
        {planTemplate(template, TEMPLATE_CATALOG).parts.map(part =>
          part.kind === 'interactive-demo' ? (
            <div key={part.key}>
              <PreviewRow>
                <DocumentIcon aria-hidden />
                <span>Welcome</span>
              </PreviewRow>
              <PreviewRow>
                <TableIcon aria-hidden />
                <span>Board</span>
              </PreviewRow>
              <PreviewRow>
                <ChatIcon aria-hidden />
                <span>Team chat</span>
              </PreviewRow>
            </div>
          ) : (
            <PreviewRow key={part.key}>
              {part.kind === 'table' ? (
                <TableIcon aria-hidden />
              ) : (
                <DocumentIcon aria-hidden />
              )}
              <span>{part.name}</span>
            </PreviewRow>
          ),
        )}
      </SidebarPreview>
    </>
  );
}

const PreviewRow = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  svg {
    width: 1em;
    flex-shrink: 0;
  }
`;

const Gallery = styled.div`
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  @media (max-width: 650px) {
    grid-template-columns: minmax(0, 1fr);
  }
  gap: ${p => p.theme.size(2)};
`;
const SidebarPreview = styled.div`
  background: ${p => p.theme.colors.bg1};
  border-radius: ${p => p.theme.radius};
  padding: ${p => p.theme.size(2)};
  font-size: 0.9rem;
  line-height: 2;
`;
