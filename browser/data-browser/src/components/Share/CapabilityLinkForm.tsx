import { useCallback, useState, type JSX } from 'react';
import {
  useCurrentAgent,
  useResource,
  useStore,
  useTitle,
  type Resource,
} from '@tomic/react';
import { issueCapabilityLink, type CapabilityMode } from '@tomic/lib';
import toast from 'react-hot-toast';
import styled from 'styled-components';
import { Button } from '../Button';
import { CodeBlock } from '../CodeBlock';
import { ErrorLook } from '../ErrorLook';
import { Column, Row } from '../Row';
import { fetchPrivateDriveSubject } from '@helpers/privateDrive';

interface CapabilityLinkFormProps {
  /** The resource the link will open. */
  target: Resource;
}

/**
 * Mints a capability link for one resource: a URL that opens it for whoever
 * holds the URL, with no account and nothing to accept. The right lives in
 * the link. It is listed under App keys as "Link: <title>", and revoking that
 * key revokes the link.
 */
export function CapabilityLinkForm({
  target,
}: CapabilityLinkFormProps): JSX.Element {
  const store = useStore();
  const [agent] = useCurrentAgent();
  const resource = useResource(target.subject);
  const [title] = useTitle(resource);
  const [mode, setMode] = useState<CapabilityMode>('read');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<Error | undefined>();
  const [result, setResult] = useState<
    { link: string; webLink?: string } | undefined
  >();

  const create = useCallback(async () => {
    setBusy(true);
    setErr(undefined);

    try {
      if (!agent) {
        throw new Error('Sign in to create a link');
      }

      // The link's agent gets a profile resource like any app key. It lives
      // under the owner's private drive, where the owner can write; a
      // parentless agent resource is one only that agent itself could save.
      const parent = await fetchPrivateDriveSubject(store, agent);

      if (!parent) {
        throw new Error('No private drive to keep the link key in');
      }

      const issued = await issueCapabilityLink(
        store,
        {
          target: target.subject,
          name: `Link: ${title ?? target.subject}`,
          mode,
          url: originOf(store.getServerUrl()),
          parent,
        },
        window.location.origin,
      );
      setResult({ link: issued.link, webLink: issued.webLink });
      await navigator.clipboard.writeText(issued.webLink ?? issued.link);
      toast.success('Link created and copied');
    } catch (e) {
      setErr(e as Error);
    } finally {
      setBusy(false);
    }
  }, [store, agent, target.subject, title, mode]);

  if (result) {
    return (
      <Column gap='1rem'>
        <p key='hint'>
          <span>{`Anyone with this link can ${mode === 'write' ? 'edit' : 'view'} `}</span>
          <strong>{title ?? target.subject}</strong>
          <span>
            {`. Treat it like a password for this resource. To take it back, revoke the key named "Link: ${title ?? target.subject}" under App keys.`}
          </span>
        </p>
        <CodeBlock key='link' content={result.webLink ?? result.link} />
        {result.webLink && (
          <Muted key='deep'>
            <span>Deep-link form, for apps that register </span>
            <code>atomic:</code>
            <CodeBlock content={result.link} />
          </Muted>
        )}
      </Column>
    );
  }

  return (
    <Column gap='1rem'>
      <p key='intro'>
        A link that opens this resource for whoever has it. No account, nothing
        to accept. The right is in the link, so share it like a password.
      </p>
      <Row key='mode' gap='1.5rem'>
        <Choice key='view'>
          <input
            type='radio'
            name='capability-mode'
            checked={mode === 'read'}
            onChange={() => setMode('read')}
          />
          <span>View</span>
        </Choice>
        <Choice key='edit'>
          <input
            type='radio'
            name='capability-mode'
            checked={mode === 'write'}
            onChange={() => setMode('write')}
          />
          <span>Edit</span>
        </Choice>
      </Row>
      <Row key='actions'>
        <Button onClick={create} disabled={busy}>
          {busy ? 'Creating…' : 'Create link'}
        </Button>
      </Row>
      {err && <ErrorLook key='error'>{err.message}</ErrorLook>}
    </Column>
  );
}

/** A bare origin, or nothing when the store has no reachable server. */
function originOf(serverUrl: string | undefined): string | undefined {
  if (!serverUrl) {
    return undefined;
  }

  try {
    const url = new URL(serverUrl);

    return url.protocol.startsWith('http') ? url.origin : undefined;
  } catch {
    return undefined;
  }
}

/** A radio and its caption. Text kept in its own element, see the form. */
const Choice = styled.label`
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  cursor: pointer;
`;

const Muted = styled.div`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.85rem;
`;
