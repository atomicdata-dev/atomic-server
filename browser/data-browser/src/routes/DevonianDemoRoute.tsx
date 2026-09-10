import { createLazyRoute } from '@tanstack/react-router';
import { useEffect, useRef, useState } from 'react';
import { useStore } from '@tomic/react';
import { Main } from '@components/Main';
import { ContainerWide } from '@components/Containers';
import { Column, Row as Horizontal } from '@components/Row';
import { Card } from '@components/Card';
import { Button } from '@components/Button';
import { AtomicLink } from '@components/AtomicLink';
import Field from '@components/forms/Field';
import { Input, ErrMessage } from '@components/forms/InputStyles';
import {
  openDemo,
  connectDemo,
  resumeDemo,
  syncDemo,
  demoRows,
  editAtomic,
  editFixture,
  type Demo,
  type Row,
} from '../chunks/DevonianDemo/demo.mjs';

function DevonianDemo() {
  const store = useStore();
  const [demo, setDemo] = useState<Demo>();
  const [rows, setRows] = useState<Row[]>([]);
  const [proxy, setProxy] = useState('https://localthought.io');
  const [repository, setRepository] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [status, setStatus] = useState('');
  const [text, setText] = useState('');

  const run = async (work: () => Promise<Demo | undefined>) => {
    setBusy(true);
    setError('');

    try {
      const current = await work();

      if (current) {
        setDemo({ ...current });
        setRows(await demoRows(store, current));
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const resumed = useRef(false);
  useEffect(() => {
    if (resumed.current) return;
    resumed.current = true;
    void run(() => resumeDemo(store));
  }, [store]);
  const start = (sample: boolean) =>
    run(async () => {
      if (!sample) {
        await connectDemo(store, { repository, proxy });

        return;
      }

      const opened = await openDemo(store, { sample, repository, proxy });
      if (sample) await syncDemo(store, opened);

      return opened;
    });
  const sync = () =>
    run(async () => {
      if (!demo) return;
      const count = await syncDemo(store, demo);
      setStatus(`Synchronized ${count} issues and comments.`);

      return demo;
    });
  const edit = (
    side: 'atomic' | 'fixture',
    command: string,
    id?: string | number,
  ) =>
    run(async () => {
      if (!demo) return;
      if (side === 'atomic')
        await editAtomic(store, demo, command, id as string, text);
      else await editFixture(demo, command, id as number, text);
      setText('');

      return demo;
    });

  return (
    <Main>
      <ContainerWide>
        <Column gap='1.5rem'>
          <h1>Devonian issue tracker demo</h1>
          <p>
            Sync issues and comments in both directions. Devonian runs in this
            browser; the Atomic tracker is stored on this device.
          </p>
          {!demo && (
            <>
              <Button disabled={busy} onClick={() => start(true)}>
                Try sample data
              </Button>
              <details>
                <summary>Connect a real GitHub repository</summary>
                <Column gap='0.75rem'>
                  <p>
                    LocalThought will ask you to sign in and authorize the
                    GitHub connection.
                  </p>
                  <Field fieldId='devonian-proxy' label='Integration proxy URL'>
                    <Input
                      id='devonian-proxy'
                      value={proxy}
                      onChange={e => setProxy(e.target.value)}
                    />
                  </Field>
                  <Field
                    fieldId='devonian-repo'
                    label='GitHub repository (owner/repo)'
                  >
                    <Input
                      id='devonian-repo'
                      value={repository}
                      onChange={e => setRepository(e.target.value)}
                    />
                  </Field>
                  <Button
                    disabled={busy || !repository}
                    onClick={() => start(false)}
                  >
                    Connect GitHub tracker
                  </Button>
                </Column>
              </details>
            </>
          )}
          {demo && (
            <>
              <p>
                {demo.state.options.sample
                  ? 'Sample mode: the GitHub side below is a browser fixture. No requests are sent to GitHub.'
                  : 'Live mode: Sync now creates and updates real GitHub issues and comments. Keep this tab open to sync.'}
              </p>
              <Horizontal>
                <Button disabled={busy} onClick={sync}>
                  {busy ? 'Working…' : 'Sync now'}
                </Button>
                <Button
                  disabled={busy}
                  onClick={() => {
                    setDemo(undefined);
                    setRows([]);
                    setError('');
                    setStatus('');
                  }}
                >
                  Connect another tracker
                </Button>
                <AtomicLink subject={demo.state.config.connection.table}>
                  Open Atomic kanban
                </AtomicLink>
              </Horizontal>
              <Field fieldId='devonian-text' label='New issue title or comment'>
                <Input
                  id='devonian-text'
                  value={text}
                  onChange={e => setText(e.target.value)}
                />
              </Field>
              <Horizontal wrapItems>
                <Button
                  disabled={busy || !text.trim()}
                  onClick={() => edit('atomic', 'create')}
                >
                  Create Atomic issue
                </Button>
                {demo.state.options.sample && (
                  <Button
                    disabled={busy || !text.trim()}
                    onClick={() => edit('fixture', 'create')}
                  >
                    Create sample GitHub issue
                  </Button>
                )}
              </Horizontal>
              <section aria-label='Atomic issues'>
                <h2>Atomic tracker</h2>
                <Column gap='0.75rem'>
                  {rows.map(row => (
                    <Card key={row.id} data-testid='atomic-issue'>
                      <Column>
                        <AtomicLink subject={row.id}>
                          {row.value.title}
                        </AtomicLink>
                        <span>{row.value.status}</span>
                        <Horizontal>
                          <Button
                            disabled={busy}
                            onClick={() => edit('atomic', 'toggle', row.id)}
                          >
                            {row.value.status === /* @wc-ignore */ 'Done'
                              ? 'Reopen Atomic issue'
                              : 'Close Atomic issue'}
                          </Button>
                          <Button
                            disabled={busy || !text.trim()}
                            onClick={() => edit('atomic', 'comment', row.id)}
                          >
                            Add Atomic comment
                          </Button>
                        </Horizontal>
                        {row.comments.map(comment => (
                          <p key={comment.id}>{comment.value.body}</p>
                        ))}
                      </Column>
                    </Card>
                  ))}
                </Column>
              </section>
              {demo.state.options.sample && (
                <section aria-label='Sample GitHub issues'>
                  <h2>Sample GitHub tracker</h2>
                  <Column gap='0.75rem'>
                    {demo.state.fixture.issues?.map(issue => (
                      <Card key={issue.number}>
                        <Column>
                          <strong>
                            #{issue.number} {issue.title}
                          </strong>
                          <span>{issue.state}</span>
                          <Horizontal>
                            <Button
                              disabled={busy}
                              onClick={() =>
                                edit('fixture', 'toggle', issue.number)
                              }
                            >
                              {issue.state === 'closed'
                                ? 'Reopen sample GitHub issue'
                                : 'Close sample GitHub issue'}
                            </Button>
                            <Button
                              disabled={busy || !text.trim()}
                              onClick={() =>
                                edit('fixture', 'comment', issue.number)
                              }
                            >
                              Add sample GitHub comment
                            </Button>
                          </Horizontal>
                          {demo.state.fixture.comments
                            ?.filter(c =>
                              c.issue_url.endsWith(`/${issue.number}`),
                            )
                            .map(c => (
                              <p key={c.id}>{c.body}</p>
                            ))}
                        </Column>
                      </Card>
                    ))}
                  </Column>
                </section>
              )}
            </>
          )}
          <p role='status'>{status}</p>
          {error && <ErrMessage role='alert'>{error}</ErrMessage>}
        </Column>
      </ContainerWide>
    </Main>
  );
}

export const devonianDemoRouteLazy = createLazyRoute('/app/devonian-demo')({
  component: DevonianDemo,
});
