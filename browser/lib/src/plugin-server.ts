import { signRequest } from './authentication.js';
import { errorMessageFromResponse } from './error.js';
import type { Store } from './store.js';

/** Execute JS in the host sandbox. Returns data/proposals; never applies them. */
export async function executeServerPlugin(
  store: Pick<Store, 'getAgent' | 'getServerUrl'>,
  request: { drive: string; plugin: string; source: string; input: unknown },
): Promise<{ verdict: string | null; error: string | null }> {
  const agent = store.getAgent();
  if (!agent) throw new Error('Not signed in');
  const url = `${store.getServerUrl()}/plugin-run`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      ...(await signRequest(url, agent, {})),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ ...request, input: JSON.stringify(request.input) }),
  });
  if (!response.ok)
    throw new Error(
      errorMessageFromResponse(await response.text(), response.status),
    );
  const body = await response.json();
  if (
    !body ||
    (body.verdict !== null &&
      body.verdict !== undefined &&
      typeof body.verdict !== 'string') ||
    (body.error !== null &&
      body.error !== undefined &&
      typeof body.error !== 'string')
  )
    throw new Error('Invalid plugin runtime response');

  return { verdict: body.verdict ?? null, error: body.error ?? null };
}
