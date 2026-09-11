import { createRoute } from '@tanstack/react-router';
import { useEffect, useState, type JSX } from 'react';
import styled from 'styled-components';
import { Agent, useCurrentAgent, useStore } from '@tomic/react';
import {
  CapabilityLinkError,
  decodeCapabilityLink,
  resolveDriveOrigins,
  type CapabilityLink,
} from '@tomic/lib';
import { pathNames } from './paths';
import { appRoute } from './RootRoutes';
import { Main } from '@components/Main';
import { Button } from '@components/Button';
import { Column, Row } from '@components/Row';
import { ErrorLook } from '@components/ErrorLook';
import { constructOpenURL } from '@helpers/navigation';
import { saveAgentToIDB } from '@helpers/agentStorage';
import { useNavigateWithTransition } from '@hooks/useNavigateWithTransition';

export type OpenRouteSearch = {
  v?: string;
  subject?: string;
  cap?: string;
  drive?: string;
  url?: string;
};

/**
 * `/app/open?v=1&subject=…&cap=…&drive=…&url=…`: opens a resource with the
 * right carried in a capability link (`@tomic/lib` `capability.ts`).
 *
 * Where to fetch from: the link's `url` when it has one. Otherwise its
 * `drive` is looked up through pkarr, which names the nodes serving that
 * drive (`@tomic/lib` `pkarr.ts`). With neither, the current node is tried.
 *
 * With nobody signed in, the link's agent becomes this browser's session, a
 * guest identity like the demo's: kept in IndexedDB so a reload still opens
 * the resource, never adopted as the device node's identity. With someone
 * signed in, their own rights are tried first; the link's right is offered as
 * a switch, not applied silently, because switching identity mid-session is
 * not something a URL should do on its own.
 */
export const OpenRoute = createRoute({
  path: pathNames.open,
  component: () => <OpenPage />,
  getParentRoute: () => appRoute,
  validateSearch: (search): OpenRouteSearch => ({
    v: search.v as string | undefined,
    subject: search.subject as string | undefined,
    cap: search.cap as string | undefined,
    drive: search.drive as string | undefined,
    url: search.url as string | undefined,
  }),
});

function OpenPage(): JSX.Element {
  const search = OpenRoute.useSearch();
  const store = useStore();
  const [agent] = useCurrentAgent();
  const navigate = useNavigateWithTransition();
  const [error, setError] = useState<string>();
  const [link, setLink] = useState<CapabilityLink>();

  useEffect(() => {
    try {
      const params = new URLSearchParams();

      for (const [key, value] of Object.entries(search)) {
        if (value !== undefined) params.set(key, value);
      }

      setLink(decodeCapabilityLink(params.toString()));
    } catch (e) {
      setError(
        e instanceof CapabilityLinkError && e.code === 'unsupported-version'
          ? 'This link was made by a newer version of the app. Update and try again.'
          : 'This link is not a valid capability link.',
      );
    }
  }, [search]);

  const openWithLink = async (target: CapabilityLink) => {
    try {
      const origin = target.url ?? (await originByPkarr(target.drive));

      if (origin && origin !== store.getServerUrl()) {
        store.setServerUrl(origin);
      }

      const linkAgent = Agent.fromSecret(target.cap, 'js');
      store.setAgent(linkAgent);
      // A link's identity is a guest: it must survive a reload of this tab
      // but never become what the device's node signs AUTH with.
      await saveAgentToIDB(target.cap, { adoptOnDevice: false });
      navigate({ to: constructOpenURL(target.subject) });
    } catch (e) {
      setError((e as Error).message);
    }
  };

  useEffect(() => {
    if (link === undefined || agent?.subject) {
      return;
    }

    void openWithLink(link);
    // Runs once per decoded link while nobody is signed in.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [link]);

  if (error) {
    return (
      <Main>
        <Center>
          <Column>
            <h1>Cannot open link</h1>
            <ErrorLook>{error}</ErrorLook>
          </Column>
        </Center>
      </Main>
    );
  }

  if (link !== undefined && agent?.subject) {
    return (
      <Main>
        <Center>
          <Column gap='1rem'>
            <h1>Open shared resource</h1>
            <p>
              You are signed in. Open it with your own account, or use the
              access this link carries. Using the link signs you out of this
              browser and continues as the link&apos;s guest identity.
            </p>
            <Row gap='1rem'>
              <Button
                onClick={() => navigate({ to: constructOpenURL(link.subject) })}
              >
                Open with my account
              </Button>
              <Button subtle onClick={() => void openWithLink(link)}>
                Use the link&apos;s access
              </Button>
            </Row>
          </Column>
        </Center>
      </Main>
    );
  }

  return (
    <Main>
      <Center>
        <p>Opening…</p>
      </Center>
    </Main>
  );
}

/**
 * The first origin the drive's pkarr record lists, or nothing when the link
 * names no drive or nobody has announced one. A failed lookup is not an
 * error: the resource may well be on the node this app already talks to.
 */
async function originByPkarr(drive: string | undefined): Promise<string | undefined> {
  if (!drive) {
    return undefined;
  }

  try {
    const [origin] = await resolveDriveOrigins(drive);

    return origin;
  } catch (e) {
    console.warn('pkarr lookup failed for', drive, e);

    return undefined;
  }
}

const Center = styled.div`
  display: grid;
  height: 100%;
  width: 100%;
  place-items: center;
`;
