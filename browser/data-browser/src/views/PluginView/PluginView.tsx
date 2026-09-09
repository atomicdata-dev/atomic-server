import { grantIdentity } from './grantIdentity';
import type { ResourcePageProps } from '../ResourcePage';
import { useCurrentAgent, useStore } from '@tomic/react';
import { useSettings } from '@helpers/AppSettings';
import { usePluginRPC } from '@views/PluginView/pluginRPC';
import styled from 'styled-components';

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

  return (
    <>
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
