import { paths } from '../routes/paths';

const CONNECT_LINKS = ['/app/authorize-mcp?', '/app/connect-agent?'];

/**
 * Where to go after signing in, from the `return_to` param: `agent`, or a
 * connect-an-app link. Anything else, an absolute URL included, is refused so
 * a link can never send someone elsewhere.
 */
export function parseReturnPath(value: string | null): string | undefined {
  if (value === 'agent') return paths.agentSettings;

  return value && CONNECT_LINKS.some(prefix => value.startsWith(prefix))
    ? value
    : undefined;
}

/** The welcome route, which brings the person back to this page after signing in. */
export const signInPath = (here: { pathname: string; search: string }) =>
  `${paths.welcome}?return_to=${encodeURIComponent(here.pathname + here.search)}`;
