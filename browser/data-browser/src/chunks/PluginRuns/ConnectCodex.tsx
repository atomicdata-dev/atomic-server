import { useState } from 'react';
import { useStore } from '@tomic/react';
import { Button } from '@components/Button';
import { Column } from '@components/Row';
import { CodeBlock } from '@components/CodeBlock';
import { ErrMessage } from '@components/forms/InputStyles';
import { useNavigateWithTransition } from '@hooks/useNavigateWithTransition';
import { constructOpenURL } from '@helpers/navigation';
import { installApp } from '../../../../../plugin-examples/codex-chat/install';
import source from '../../../../../plugin-examples/codex-chat/view.js?raw';

export function ConnectCodex({ drive }: { drive: string }) {
  const store = useStore();
  const navigate = useNavigateWithTransition();
  const [installed, setInstalled] =
    useState<Awaited<ReturnType<typeof installApp>>>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const create = async () => {
    setBusy(true);
    setError(undefined);
    try {
      setInstalled(await installApp(store, drive, source));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const download = () => {
    if (!installed) return;
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(installed, null, 2)], {
        type: 'application/json',
      }),
    );
    const a = document.createElement('a');
    a.href = url;
    a.download = 'codex-setup.json';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return (
    <Column>
      <p>
        Chat with Codex inside Atomic. Messages are saved here before your local
        worker sends them to Codex. Replies are saved back into the
        conversation.
      </p>
      <p>
        The worker runs on your computer with your Codex sign-in and a workspace
        you choose locally. Installing the app does not start it.
      </p>
      {!installed ? (
        <Button
          onClick={create}
          disabled={busy}
          loading={busy ? 'Creating…' : undefined}
        >
          Create Codex app
        </Button>
      ) : (
        <>
          <p>
            Codex app created. Download its worker setup, then run these
            commands from your AtomicServer checkout after building the Codex
            example.
          </p>
          <Button onClick={download}>Download worker setup</Button>
          <p>
            The setup file contains a credential scoped to this app. Keep it
            private. Anyone with write access to the app can submit prompts and
            answer approvals for the worker.
          </p>
          <CodeBlock
            content={
              /* @wc-ignore */ 'node plugin-examples/codex-chat/dist/cli.js connect ~/Downloads/codex-setup.json ./codex-connection.json /absolute/workspace\nnode plugin-examples/codex-chat/dist/cli.js work ./codex-connection.json'
            }
            wordWrap
          />
          <Button
            onClick={() => navigate(constructOpenURL(installed.config.app))}
          >
            Open Codex
          </Button>
        </>
      )}
      {error && <ErrMessage>{error}</ErrMessage>}
    </Column>
  );
}
