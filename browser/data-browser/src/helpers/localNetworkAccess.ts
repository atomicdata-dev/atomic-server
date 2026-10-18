import { useLocalStorage } from '@hooks/useLocalStorage';
import { isRunningInTauri } from './tauri';
import { isLoopbackHost } from './runtimeSetting';

/**
 * Chrome asks "wants to access other apps and services on this device" the
 * first time a public page fetches a loopback or private address. These helpers
 * let callers hold such a fetch back until the user has been told why.
 */

const PRIVATE_IPV4 =
  /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)\d{1,3}(\.\d{1,3}){0,2}$/;

/** `rawHost` is as `URL.hostname` gives it, so IPv6 keeps its brackets. */
function isLocalHostname(rawHost: string): boolean {
  const host = rawHost.toLowerCase();

  return (
    isLoopbackHost(host) || host.endsWith('.local') || PRIVATE_IPV4.test(host)
  );
}

/** True for loopback, private-range, link-local and `.local` addresses. */
export function isLocalNetworkUrl(url: string): boolean {
  try {
    return isLocalHostname(new URL(url).hostname);
  } catch {
    return false;
  }
}

/**
 * True when fetching `url` from this page makes the browser ask for local
 * network permission: the target is local while the page itself is not. Dev on
 * localhost and the desktop app never need it.
 */
export function requiresLocalNetworkPermission(url: string): boolean {
  if (typeof window === 'undefined' || isRunningInTauri()) return false;

  return isLocalNetworkUrl(url) && !isLocalHostname(window.location.hostname);
}

export function useLocalNetworkExplained() {
  const [explained, markExplained] = useLocalStorage<boolean>(
    'atomic.localNetwork.explained',
    false,
  );

  return { explained, markExplained: () => markExplained(true) };
}

/** True while `url` would trigger the browser prompt before the user was told. */
export function useLocalNetworkBlocked(url: string | undefined): boolean {
  const { explained } = useLocalNetworkExplained();

  return Boolean(url) && !explained && requiresLocalNetworkPermission(url!);
}
