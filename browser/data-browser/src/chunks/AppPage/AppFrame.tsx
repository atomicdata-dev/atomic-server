import { isViewRequest } from '@tomic/plugin';
import { viewSession } from '@helpers/extensions/viewSession';
import { useEffect, useRef, useState } from 'react';
import { styled } from 'styled-components';
import {
  errorMessageFromResponse,
  signRequest,
  useResource,
  useStore,
  useTitle,
} from '@tomic/react';
import { findSchema, pluginSchema } from '@tomic/lib';
import { FrameBridge } from '@helpers/extensions/FrameBridge';
import {
  appChanges,
  handleRequest,
  isHostRequest,
  isWithinApp,
  type HostReply,
} from './hostStore';
import { LoaderBlock } from '@components/Loader';
import { Button } from '@components/Button';
import { Row } from '@components/Row';
import { newContextItem, useAISidebar } from '@components/AI/AISidebarContext';
import type { AIAtomicResourceMessageContext } from '@chunks/AI/types';

import resetCss from '../../reset.css?raw';
import {
  useCreateThemeVars,
  useFrameColorScheme,
} from '@views/PluginView/useCreateThemeVars';
import { getIntegrationProxy } from '@helpers/integrationProxy';
import {
  isPlatformId,
  ProxyConnections,
  type ProxyConnection,
} from '@helpers/proxyConnections';
import { appAgentOf } from './appAgent';
import { ConnectDialog } from './ConnectDialog';
import { useHostUI } from '@components/HostUI/hostUI';
import type { ViewChanges } from '@helpers/extensions/viewApply';

/** Changing installation or destination must discard source tokens and pending replies. */
export function AppFrame(props: Parameters<typeof AppFrameSession>[0]) {
  return (
    <AppFrameSession
      key={JSON.stringify([props.app, props.drive, props.table])}
      {...props}
    />
  );
}

/**
 * Renders an app's view, which lives in the drive rather than on the server's
 * filesystem.
 *
 * The iframe is null-origin, so it cannot sign a request for its own source —
 * the authenticated page mints it a short-lived capability instead and puts it
 * in the URL. Loading via `src` rather than `srcdoc` matters for the same
 * reason it does for installed plugins: a `srcdoc`, `blob:` or `data:` frame
 * inherits this page's CSP and the app's script would be blocked.
 */
function AppFrameSession({
  app,
  drive,
  table,
  onOutcome,
  silent,
}: {
  app: string;
  drive: string;
  /**
   * The table this app is a view of, when it is being used as one.
   *
   * Without it an app reads its own rows. With it, the same app can be
   * pointed at rows someone already has — which is the difference between an
   * app that owns its data and an app that is a way of looking at data.
   */
  table?: string;
  /**
   * Told once, when the app either finishes rendering or fails.
   *
   * This is what lets something other than a person watch an app run — the
   * check that happens right after a model writes one, before it reports
   * success.
   */
  onOutcome?: (outcome: AppOutcome) => void;
  /** Report the outcome, but do not draw the error bar. For an unattended run. */
  silent?: boolean;
}): React.JSX.Element {
  const store = useStore();
  const [src, setSrc] = useState<string>();
  const [entrypoint, setEntrypoint] = useState<string | null>();
  const [problem, setProblem] = useState<string>();
  const [appError, setAppError] = useState<AppError>();
  // An app asking to connect a proxy platform. Drawn by this page, not the
  // frame, so only a click the person makes here can navigate away.
  const [connectAsk, setConnectAsk] = useState<ConnectAsk>();
  const connectAskRef = useRef<ConnectAsk | undefined>(undefined);
  const [appTitle] = useTitle(useResource(app));
  const { askAI } = useAISidebar();
  const frameRef = useRef<HTMLIFrameElement>(null);
  // Held in a ref so an inline callback does not tear down the listener — and
  // with it every subscription — on each render.
  const onOutcomeRef = useRef(onOutcome);
  onOutcomeRef.current = onOutcome;
  // Subject to the store's unsubscribe, so a view that re-renders does not
  // accumulate a listener per render and get told about one change N times.
  const bridgeRef = useRef<FrameBridge | undefined>(undefined);
  const stylesheet = useCreateThemeVars();
  const hostUI = useHostUI({
    writeRoot: app,
    mayWriteUnder: subject => isWithinApp(store, subject, app),
    appTitle,
    frame: frameRef,
    table,
  });
  const { handle: handleUI, forwardKey } = hostUI;
  const colorScheme = useFrameColorScheme();

  // Which plugin renders it. Resolved here rather than by each caller: a
  // table tab and an app page both need it, and two copies would drift.
  useEffect(() => {
    let cancelled = false;

    (async () => {
      const schema = await findSchema(store, drive, pluginSchema());
      const property = schema.properties?.entrypoint;
      // Read through the store rather than from a passed resource, so this
      // depends on a subject string instead of a proxy whose identity churns.
      const resource = await store.getResource(app);
      const found = property
        ? (resource.get(property) as string | undefined)
        : undefined;

      if (!cancelled) setEntrypoint(found ?? null);
    })().catch(() => {
      if (!cancelled) setEntrypoint(null);
    });

    return () => {
      cancelled = true;
    };
  }, [store, drive, app]);

  useEffect(() => {
    if (!entrypoint) return;

    let cancelled = false;

    mintViewToken(store, drive, entrypoint)
      .then(result => {
        if (cancelled) return;

        if (!result.ok) {
          setProblem(result.error);

          return;
        }

        const query = new URLSearchParams({
          drive,
          plugin: entrypoint,
          token: result.token,
          format: 'html',
        });
        setSrc(`${store.getServerUrl()}/plugin-ui?${query.toString()}`);
      })
      .catch((e: Error) => {
        if (!cancelled) setProblem(e.message);
      });

    return () => {
      cancelled = true;
    };
  }, [store, drive, entrypoint, app]);

  useEffect(() => {
    const frame = frameRef.current;
    if (!frame) return;
    // Per frame: `undo` reverts what this frame applied, nothing older.
    const changes = appChanges(store, drive, app);
    const bridge = new FrameBridge(frame, (wire, originalSession) => {
      const canonical = isViewRequest(wire);
      const data = canonical
        ? { ...wire.args, __atomic: true, id: wire.id, op: wire.op }
        : wire;
      const session = canonical
        ? viewSession(originalSession, wire.id)
        : originalSession;
      const message = data as Record<string, unknown>;

      if (forwardKey(message)) return;

      if (message.type === '__atomic_plugin_error') {
        const failure: AppError = {
          message: String(message.message ?? 'Something went wrong.'),
          stack: typeof message.stack === 'string' ? message.stack : undefined,
          phase: message.phase === 'load' ? 'load' : 'runtime',
        };
        setAppError(failure);
        onOutcomeRef.current?.({ ok: false, ...failure });

        return;
      }

      if (message.type === '__atomic_plugin_rendered') {
        onOutcomeRef.current?.({
          ok: true,
          children: typeof message.children === 'number' ? message.children : 0,
        });

        return;
      }

      if (!isHostRequest(data)) return;

      if (
        handleUI(
          data as unknown as Parameters<typeof handleUI>[0],
          session.post,
        )
      ) {
        return;
      }

      if (data.op === 'proxyConnect') {
        if (!isPlatformId(data.platform)) {
          session.post({ id: data.id, error: 'platform is required' });

          return;
        }

        // One question at a time; a second ask answers the first.
        const previous = connectAskRef.current;
        previous?.reply({ id: previous.id, result: { status: 'cancelled' } });
        const ask: ConnectAsk = {
          id: data.id,
          platform: data.platform!,
          reply: session.post,
        };
        connectAskRef.current = ask;
        setConnectAsk(ask);

        // Offer a connection the person already has for this platform, so
        // using it for one more app needs no second trip through OAuth. A
        // proxy that cannot list them still lets them connect a new one.
        existingConnections(store, data.platform!)
          .catch((): ProxyConnection[] => [])
          .then(existing => {
            if (connectAskRef.current !== ask) return;
            const withExisting = { ...ask, existing };
            connectAskRef.current = withExisting;
            setConnectAsk(withExisting);
          });

        return;
      }

      if (data.op === 'subscribe' && typeof data.subject === 'string') {
        const subject = data.subject;
        session.watch(subject, () =>
          store.subscribe(subject, () =>
            session.post({ __atomicChanged: subject }),
          ),
        );
        session.post({ id: data.id, result: true });

        return;
      }

      if (data.op === 'unsubscribe' && typeof data.subject === 'string') {
        session.unwatch(data.subject);
        session.post({ id: data.id, result: true });

        return;
      }

      void answer(store, app, drive, table, data, session.post, changes);
    });
    bridgeRef.current = bridge;

    return () => {
      bridge.close();
      bridgeRef.current = undefined;
    };
  }, [store, app, drive, table, src, handleUI, forwardKey]);

  useEffect(() => {
    bridgeRef.current?.setStyle(`${resetCss}\n${stylesheet}`, colorScheme);
  }, [stylesheet, colorScheme, src]);

  // The app never got as far as running: no token, no entry point, no source.
  // Reported as a failure like any other, so a caller waiting on an outcome
  // hears now rather than sitting out the timeout for a verdict of "unknown".
  useEffect(() => {
    if (problem !== undefined) {
      onOutcomeRef.current?.({ ok: false, phase: 'load', message: problem });
    } else if (entrypoint === null) {
      onOutcomeRef.current?.({
        ok: false,
        phase: 'load',
        message:
          /* @wc-ignore */ 'This app has no entry point, so there is nothing to run.',
      });
    }
  }, [problem, entrypoint]);

  if (problem !== undefined) {
    return <Problem>{problem}</Problem>;
  }

  if (entrypoint === null) {
    return (
      <Problem>
        This app has no entry point, so there is nothing to open.
      </Problem>
    );
  }

  if (src === undefined) {
    return <LoaderBlock />;
  }

  /** Answers `ask`, unless a newer ask took its place and answered it. */
  const finishAsk = (ask: ConnectAsk, used: ProxyConnection | undefined) => {
    if (connectAskRef.current?.id !== ask.id) return;
    ask.reply({
      id: ask.id,
      result: used
        ? {
            status: 'connected',
            connectionId: used.connection_id,
            platform: used.platform,
          }
        : { status: 'cancelled' },
    });
    connectAskRef.current = undefined;
    setConnectAsk(undefined);
  };

  const connect = async (ask: ConnectAsk) => {
    if (!store.getAgent()) throw new Error('Sign in to connect an account.');

    const appAgent = await appAgentOf(store, { drive, app });
    const url = await proxyConnections(store).start(
      { drive, app, appAgent },
      ask.platform,
      location.href,
      await appLabel(store, app),
    );

    // Closing the dialog meanwhile was a no; leaving now would overrule it.
    if (connectAskRef.current?.id === ask.id) location.assign(url);
  };

  const shareExisting = async (connection: ProxyConnection) => {
    const appAgent = await appAgentOf(store, { drive, app });
    await proxyConnections(store).delegate(
      connection.connection_id,
      appAgent,
      await appLabel(store, app),
    );
  };

  const fixIt = () => {
    if (!appError) return;

    askAI({
      // Written as what the user would say, because it becomes the first
      // message of the chat and they have to be able to read it back.
      prompt: /* @wc-ignore */ [
        'The app I have open just hit an error. Read its source with',
        'describe_app, work out what went wrong, and fix it with update_app.',
        '',
        `Error (${appError.phase === 'load' ? 'while opening the app' : 'while using it'}): ${appError.message}`,
        ...(appError.stack ? ['', 'Stack:', appError.stack] : []),
      ].join('\n'),
      context: [
        newContextItem<AIAtomicResourceMessageContext>({
          type: 'atomic-resource',
          subject: app,
        }),
      ],
    });
  };

  return (
    <Wrapper>
      {appError && !silent && (
        <ErrorBar role='alert'>
          <ErrorText>
            <strong>This app hit an error.</strong> {appError.message}
          </ErrorText>
          <Row gap='0.5rem'>
            <Button onClick={fixIt}>Fix it</Button>
            <Button subtle onClick={() => setAppError(undefined)}>
              Dismiss
            </Button>
          </Row>
        </ErrorBar>
      )}
      {hostUI.element}
      {connectAsk && (
        <ConnectDialog
          app={appTitle}
          platform={platformName(connectAsk.platform)}
          proxySite={new URL(getIntegrationProxy()).host}
          existing={connectAsk.existing}
          onConnect={() => connect(connectAsk)}
          onUseExisting={shareExisting}
          onClosed={used => finishAsk(connectAsk, used)}
        />
      )}
      <Frame
        ref={frameRef}
        src={src}
        // `allow-modals` because confirm() and alert() are the first things
        // an app reaches for to guard a delete, and without it they return
        // false silently — the button does nothing and nothing says why. Still
        // no allow-same-origin, so the frame stays null-origin and cannot
        // touch this page.
        sandbox='allow-scripts allow-modals'
        title='App'
      />
    </Wrapper>
  );
}

/** How a run of an app ended. */
export type AppOutcome =
  | { ok: true; children: number }
  | ({ ok: false } & AppError);

/** What the frame told us went wrong. */
export interface AppError {
  message: string;
  stack?: string;
  /** Whether the app failed to open at all, or broke while being used. */
  phase: 'load' | 'runtime';
}

/**
 * Serving one request, shaped so failures come back to the app as errors it
 * can render rather than as a promise nobody is watching.
 */
async function answer(
  store: ReturnType<typeof useStore>,
  app: string,
  drive: string,
  table: string | undefined,
  request: Parameters<typeof handleRequest>[3],
  post: (reply: HostReply) => void,
  changes: ViewChanges,
): Promise<void> {
  try {
    post({
      id: request.id,
      result: await handleRequest(
        store,
        app,
        drive,
        request,
        table,
        proxyHost(store, app, drive),
        changes,
      ),
    });
  } catch (e) {
    post({ id: request.id, error: (e as Error).message });
  }
}

/** The configured proxy, managed with the signed-in user's key. */
function proxyConnections(store: ReturnType<typeof useStore>) {
  return new ProxyConnections(localStorage, getIntegrationProxy(), () =>
    store.getAgent(),
  );
}

/**
 * Each app's agent, looked up once per page. A failed lookup is forgotten so
 * the next request tries again (the app may get an identity meanwhile).
 */
const appAgents = new Map<string, Promise<string>>();

function cachedAppAgent(
  store: ReturnType<typeof useStore>,
  drive: string,
  app: string,
): Promise<string> {
  const key = JSON.stringify([store.getServerUrl(), drive, app]);
  let found = appAgents.get(key);

  if (!found) {
    found = appAgentOf(store, { drive, app });
    found.catch(() => appAgents.delete(key));
    appAgents.set(key, found);
  }

  return found;
}

/** This app's integration-proxy access, or none when signed out. */
function proxyHost(
  store: ReturnType<typeof useStore>,
  app: string,
  drive: string,
) {
  return store.getAgent()
    ? proxyConnections(store).host(() => cachedAppAgent(store, drive, app))
    : undefined;
}

/** The person's own connections for `platform`, most recently used first. */
async function existingConnections(
  store: ReturnType<typeof useStore>,
  platform: string,
): Promise<ProxyConnection[]> {
  if (!store.getAgent()) return [];
  const rows = await proxyConnections(store).list(platform);

  return rows.sort((a, b) =>
    String(b.last_used_at ?? b.created_at ?? '').localeCompare(
      String(a.last_used_at ?? a.created_at ?? ''),
    ),
  );
}

/** What a delegation is labelled with at the proxy: the app's name. */
async function appLabel(
  store: ReturnType<typeof useStore>,
  app: string,
): Promise<string> {
  try {
    return (await store.getResource(app)).title || app;
  } catch {
    return app;
  }
}

/** `pets` -> `Pets`, `github-issues` -> `Github Issues`. */
function platformName(id: string) {
  return id
    .split('-')
    .map(word => `${word[0]?.toUpperCase() ?? ''}${word.slice(1)}`)
    .join(' ');
}

interface ConnectAsk {
  id: number | string;
  platform: string;
  reply: (reply: HostReply) => void;
  /** Connections the person already has for this platform; unset while looking. */
  existing?: ProxyConnection[];
}

type MintResult = { ok: true; token: string } | { ok: false; error: string };

/**
 * Asking for the capability, shaped as a result rather than an exception: the
 * React Compiler cannot compile try/catch inside a component, and this is
 * called from one.
 */
async function mintViewToken(
  store: ReturnType<typeof useStore>,
  drive: string,
  plugin: string,
): Promise<MintResult> {
  const agent = store.getAgent();

  if (!agent) return { ok: false, error: 'Sign in to open this app.' };

  const url = `${store.getServerUrl()}/plugin-view-token`;

  try {
    const headers = await signRequest(url, agent, {});
    const response = await fetch(url, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({ drive, plugin }),
    });

    if (!response.ok) {
      return {
        ok: false,
        error: errorMessageFromResponse(await response.text(), response.status),
      };
    }

    const body = (await response.json()) as { token: string };

    return { ok: true, token: body.token };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

const Frame = styled.iframe`
  border: none;
  width: 100%;
  /* An iframe never grows to fit its document: whatever height it is given is
   * the height the app gets, and anything taller is clipped. So take the whole
   * box the caller sized, and let the app scroll inside it. Both callers hand
   * it a sized box; the floor is only for the case where one forgets. */
  flex: 1;
  height: 100%;
  min-height: 20rem;
  background: ${p => p.theme.colors.bg};
`;

/** Keeps the frame filling whatever is left once the error bar has taken its height. */
const Wrapper = styled.div`
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
`;

/**
 * Sits above the app rather than replacing it: an app that threw in one button
 * is usually still readable, and throwing away what the user can see is a
 * worse trade than showing a bar over it.
 */
const ErrorBar = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
  padding: 0.5rem 0.75rem;
  border: 1px solid ${p => p.theme.colors.alert};
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg1};
  margin-bottom: 0.5rem;
`;

const ErrorText = styled.span`
  color: ${p => p.theme.colors.textLight};
  overflow-wrap: anywhere;
  min-width: 0;
`;

const Problem = styled.p`
  color: ${p => p.theme.colors.alert};
`;
