// @wc-ignore-file
import { useSyncExternalStore } from 'react';
import {
  configuredProxy,
  saveProxy,
} from '../../../../integrations/localthought/settings';
import { DEFAULT_PROXY } from '../../../../integrations/localthought/browser';

export const defaultIntegrationProxy =
  import.meta.env.VITE_INTEGRATION_PROXY_URL || DEFAULT_PROXY;
export const getIntegrationProxy = () =>
  configuredProxy(localStorage, defaultIntegrationProxy);
const event = 'integration-proxy-change';

export function setIntegrationProxy(value: string) {
  saveProxy(localStorage, value);
  window.dispatchEvent(new Event(event));
}

function subscribe(listener: () => void) {
  window.addEventListener(event, listener);
  window.addEventListener('storage', listener);

  return () => {
    window.removeEventListener(event, listener);
    window.removeEventListener('storage', listener);
  };
}

export const useIntegrationProxy = () =>
  useSyncExternalStore(subscribe, getIntegrationProxy);
