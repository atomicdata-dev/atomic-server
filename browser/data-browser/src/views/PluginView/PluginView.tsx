import { grantIdentity } from './grantIdentity';
import type { ResourcePageProps } from '../ResourcePage';
import { useCurrentAgent, useStore } from '@tomic/react';
import { useSettings } from '@helpers/AppSettings';
import { usePluginRPC } from '@views/PluginView/pluginRPC';
import styled from 'styled-components';
import { useEffect, useRef, useState } from 'react';
import { signRequest } from '@tomic/lib';
import { ErrorBlock } from '@components/ErrorLook';

import resetCss from '../../reset.css?raw';
import { useCreateThemeVars } from './useCreateThemeVars';
import { useCustomViews } from '@components/CustomViewProvider';

export enum ViewType {
  Page = 'page',
  Card = 'card',
  Inline = 'inline',
}

export interface PluginViewProps extends ResourcePageProps {
  plugin: string;
}

/**
 * Renders a ResourcePage view provided by the plugin.
 *
 * The view is hosted in a sandboxed (null-origin) iframe so the plugin can't
 * touch the parent page. The iframe is loaded via `src` from the server's
 * `/plugin-ui?...&format=html` endpoint rather than `srcdoc`: a `srcdoc`
 * (or `blob:`/`data:`) iframe INHERITS the parent SPA's nonce-locked CSP, so
 * the plugin's `<script>` is blocked on any CSP-enforced (i.e. production)
 * server — dev has no parent CSP, which is why it only broke in prod. A real
 * network response gets its own CSP from the server (see plugin_ui.rs).
 *
 * Because the iframe is null-origin we can't reach into its DOM to inject the
 * reset + theme CSS, so we hand it over via `postMessage` once the iframe's
 * bootstrap signals `__atomic_plugin_ready`.
 */
export const PluginView: React.FC<PluginViewProps> = props => {
  const [agent] = useCurrentAgent();
  const { drive } = useSettings();
  const store = useStore();
  const { getUIPluginData } = useCustomViews();
  const installation = getUIPluginData(props.plugin).resource;

  return (
    <PluginViewSession
      key={grantIdentity(
        store.getServerUrl(),
        drive,
        agent?.subject ?? '',
        installation,
      )}
      {...props}
    />
  );
};

const PluginViewSession: React.FC<PluginViewProps> = ({ plugin }) => {
  const { drive } = useSettings();
  const store = useStore();
  const { getUIPluginData } = useCustomViews();
  const pluginData = getUIPluginData(plugin);
  const stylesheet = useCreateThemeVars();
  const [frameRef, resourcePickerDialog] = usePluginRPC(
    pluginData,
    `${resetCss}\n${stylesheet}`,
  );
  const pluginUrl = `${store.getServerUrl()}/plugin-ui?drive=${encodeURIComponent(drive)}&plugin=${encodeURIComponent(plugin)}`;
  const src = `${pluginUrl}&format=html`;

  const hasCss = pluginData?.uiManifest.css ?? false;
  const [loadError, setLoadError] = useState<Error>();

  // A null-origin sandbox cannot send the account cookie. Fetch assets in
  // the trusted parent with signed requests and send only their contents to
  // the frame; credentials and signing keys never enter the plugin sandbox.
  useEffect(() => {
    let cancelled = false;

    const fetchAsset = async (format: string) => {
      const url = `${pluginUrl}&format=${format}`;
      const agent = store.getAgent();
      const headers = agent ? await signRequest(url, agent, {}) : {};
      const response = await fetch(url, { headers, credentials: 'include' });
      if (!response.ok)
        throw new Error(
          /* @wc-ignore */ `Plugin asset request failed (${response.status})`,
        );

      return response.text();
    };

    const onReady = (event: MessageEvent) => {
      if (
        event.source !== frameRef.current?.contentWindow ||
        event.data?.type !== '__atomic_plugin_ready'
      )
        return;
      setLoadError(undefined);
      void Promise.all([
        fetchAsset('js'),
        hasCss ? fetchAsset('css') : Promise.resolve(''),
      ])
        .then(([js, css]) => {
          if (!cancelled)
            frameRef.current?.contentWindow?.postMessage(
              { type: '__atomic_plugin_assets', js, css },
              '*',
            );
        })
        .catch(error => {
          if (!cancelled)
            setLoadError(
              error instanceof Error ? error : new Error(String(error)),
            );
        });
    };

    window.addEventListener('message', onReady);

    return () => {
      cancelled = true;
      window.removeEventListener('message', onReady);
    };
  }, [pluginUrl, hasCss, store, frameRef]);

  // Hand the reset + theme CSS to the null-origin iframe via postMessage. The
  // iframe applies it to its `<style id="__atomic_theme">`. We (re)send on the
  // iframe's ready signal and whenever the theme changes.
  const readyRef = useRef(false);

  useEffect(() => {
    const css = `${resetCss}\n${stylesheet}`;

    const post = () =>
      frameRef.current?.contentWindow?.postMessage(
        { type: '__atomic_style', css },
        '*',
      );

    const onMessage = (e: MessageEvent) => {
      if (e.source !== frameRef.current?.contentWindow) return;

      if ((e.data as { type?: string })?.type === '__atomic_plugin_ready') {
        readyRef.current = true;
        post();
      }
    };

    window.addEventListener('message', onMessage);

    // Theme changed after the iframe was already up → push the update.
    if (readyRef.current) {
      post();
    }

    return () => window.removeEventListener('message', onMessage);
  }, [stylesheet, frameRef]);

  return (
    <>
      {loadError && <ErrorBlock error={loadError} />}
      <StyledIframe
        title='plugin-view'
        id='custom-view'
        referrerPolicy='no-referrer'
        ref={frameRef}
        src={src}
        sandbox='allow-scripts allow-downloads allow-pointer-lock allow-presentation'
      />
      {resourcePickerDialog}
    </>
  );
};

const StyledIframe = styled.iframe`
  width: 100%;
  height: 100%;
  border: none;
`;
