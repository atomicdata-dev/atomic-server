import { useCallback, useEffect, useRef, useState } from 'react';
import { styled } from 'styled-components';
import { errorMessageFromResponse, signRequest, useStore } from '@tomic/react';
import { handleRequest, isHostRequest, type HostReply } from './hostStore';
import { LoaderBlock } from '@components/Loader';

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
  entrypoint,
}: {
  app: string;
  drive: string;
  entrypoint: string;
}): React.JSX.Element {
  const store = useStore();
  const [src, setSrc] = useState<string>();
  const [problem, setProblem] = useState<string>();
  const frameRef = useRef<HTMLIFrameElement>(null);
  const stylesheet = useCreateThemeVars();

  useEffect(() => {
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

      if (!isHostRequest(e.data)) return;

      // Only from the frame this component owns. A page can host more than
      // one, and every other window on the origin can post here too.
      if (e.source !== frameRef.current?.contentWindow) return;

      void answer(store, app, e.data, reply => {
        frameRef.current?.contentWindow?.postMessage(reply, '*');
      });
    };

    window.addEventListener('message', onMessage);

    return () => window.removeEventListener('message', onMessage);
  }, [sendStyle, store, app]);

  if (problem !== undefined) {
    return <Problem>{problem}</Problem>;
  }

  if (src === undefined) {
    return <LoaderBlock />;
  }

  return (
    <Frame
      ref={frameRef}
      src={src}
      onLoad={sendStyle}
      sandbox='allow-scripts'
      title='App'
    />
  );
}

/**
 * Serving one request, shaped so failures come back to the app as errors it
 * can render rather than as a promise nobody is watching.
 */
async function answer(
  store: ReturnType<typeof useStore>,
  app: string,
  request: Parameters<typeof handleRequest>[2],
  post: (reply: HostReply) => void,
): Promise<void> {
  try {
    post({ id: request.id, result: await handleRequest(store, app, request) });
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
  height: 100%;
  min-height: 60vh;
  background: ${p => p.theme.colors.bg};
`;

const Problem = styled.p`
  color: ${p => p.theme.colors.alert};
`;
