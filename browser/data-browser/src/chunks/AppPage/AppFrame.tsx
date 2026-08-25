import { useCallback, useEffect, useRef, useState } from 'react';
import { styled } from 'styled-components';
import { errorMessageFromResponse, signRequest, useStore } from '@tomic/react';
import { findSchema, pluginSchema } from '@tomic/lib';
import { handleRequest, isHostRequest, type HostReply } from './hostStore';
import { LoaderBlock } from '@components/Loader';
import { Button } from '@components/Button';
import { Row } from '@components/Row';
import { newContextItem, useAISidebar } from '@components/AI/AISidebarContext';
import type { AIAtomicResourceMessageContext } from '@chunks/AI/types';

import resetCss from '../../reset.css?raw';
import { useCreateThemeVars } from '@views/PluginView/useCreateThemeVars';

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
export function AppFrame({
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
  const { askAI } = useAISidebar();
  const frameRef = useRef<HTMLIFrameElement>(null);
  // Held in a ref so an inline callback does not tear down the listener — and
  // with it every subscription — on each render.
  const onOutcomeRef = useRef(onOutcome);
  onOutcomeRef.current = onOutcome;
  // Subject to the store's unsubscribe, so a view that re-renders does not
  // accumulate a listener per render and get told about one change N times.
  const watching = useRef(new Map<string, () => void>());
  const stylesheet = useCreateThemeVars();

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

  // The frame is null-origin, so its DOM is unreachable from here; hand the
  // theme over the same way the plugin view does.
  const sendStyle = useCallback(() => {
    frameRef.current?.contentWindow?.postMessage(
      { type: '__atomic_style', css: `${resetCss}\n${stylesheet}` },
      '*',
    );
  }, [stylesheet]);

  useEffect(() => {
    const onMessage = (e: MessageEvent) => {
      if (e.data?.type === '__atomic_plugin_ready') {
        sendStyle();

        return;
      }

      if (e.data?.type === '__atomic_plugin_error') {
        // Only from the frame this component owns, same as every other message
        // here: any window on this origin can post, and an error attributed to
        // the wrong app sends its author to fix code that is not broken.
        if (e.source !== frameRef.current?.contentWindow) return;

        const failure: AppError = {
          message: String(e.data.message ?? 'Something went wrong.'),
          stack: typeof e.data.stack === 'string' ? e.data.stack : undefined,
          phase: e.data.phase === 'load' ? 'load' : 'runtime',
        };

        setAppError(failure);
        onOutcomeRef.current?.({ ok: false, ...failure });

        return;
      }

      if (e.data?.type === '__atomic_plugin_rendered') {
        if (e.source !== frameRef.current?.contentWindow) return;

        onOutcomeRef.current?.({
          ok: true,
          children: typeof e.data.children === 'number' ? e.data.children : 0,
        });

        return;
      }

      if (!isHostRequest(e.data)) return;

      // Only from the frame this component owns. A page can host more than
      // one, and every other window on the origin can post here too.
      if (e.source !== frameRef.current?.contentWindow) return;

      const post = (message: unknown) =>
        frameRef.current?.contentWindow?.postMessage(message, '*');

      // Subscriptions are wired here rather than in `handleRequest`, because
      // this is what owns the frame that has to be posted back to.
      if (e.data.op === 'subscribe' && e.data.subject) {
        const subject = e.data.subject;

        if (!watching.current.has(subject)) {
          watching.current.set(
            subject,
            store.subscribe(subject, () => post({ __atomicChanged: subject })),
          );
        }

        post({ id: e.data.id, result: true });

        return;
      }

      if (e.data.op === 'unsubscribe' && e.data.subject) {
        watching.current.get(e.data.subject)?.();
        watching.current.delete(e.data.subject);
        post({ id: e.data.id, result: true });

        return;
      }

      void answer(store, app, drive, table, e.data, post);
    };

    window.addEventListener('message', onMessage);
    const released = watching.current;

    return () => {
      window.removeEventListener('message', onMessage);
      // Navigating away must not leave the store notifying a frame that is
      // gone — those callbacks would keep the whole component tree alive.
      released.forEach(unsubscribe => unsubscribe());
      released.clear();
    };
  }, [sendStyle, store, app, drive, table]);

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
      <Frame
        ref={frameRef}
        src={src}
        onLoad={sendStyle}
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
): Promise<void> {
  try {
    post({
      id: request.id,
      result: await handleRequest(store, app, drive, request, table),
    });
  } catch (e) {
    post({ id: request.id, error: (e as Error).message });
  }
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

/** Keeps the frame filling whatever is left once the bar has taken its height. */
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
