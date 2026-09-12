/** Versioned UI wire contract. Authority comes from the host's view instance. */
export const VIEW_PROTOCOL_VERSION = 1;
export type ViewOperation =
  | 'app'
  | 'data'
  | 'get'
  | 'query'
  | 'create'
  | 'save'
  | 'destroy'
  | 'patch'
  | 'context'
  | 'navigate'
  | 'pickResource'
  | 'pickFile'
  | 'search'
  | 'subscribe'
  | 'unsubscribe';
export interface ViewRequest {
  type: 'atomic.view.request';
  version: 1;
  id: string | number;
  op: ViewOperation;
  args: Record<string, unknown>;
}
export interface ViewResponse {
  type: 'atomic.view.response';
  version: 1;
  id: string | number;
  result?: unknown;
  error?: string;
}
export function viewRequest(
  id: string | number,
  op: ViewOperation,
  args: Record<string, unknown> = {},
): ViewRequest {
  return {
    type: 'atomic.view.request',
    version: VIEW_PROTOCOL_VERSION,
    id,
    op,
    args,
  };
}
export function isViewRequest(value: unknown): value is ViewRequest {
  if (!value || typeof value !== 'object') return false;
  const request = value as ViewRequest;

  return (
    request.type === 'atomic.view.request' &&
    request.version === 1 &&
    ((typeof request.id === 'string' && request.id.length > 0) ||
      (typeof request.id === 'number' && Number.isSafeInteger(request.id))) &&
    [
      'app',
      'data',
      'get',
      'query',
      'create',
      'save',
      'destroy',
      'patch',
      'context',
      'navigate',
      'pickResource',
      'pickFile',
      'search',
      'subscribe',
      'unsubscribe',
    ].includes(request.op) &&
    !!request.args &&
    typeof request.args === 'object' &&
    !Array.isArray(request.args)
  );
}

/** Existing package APIs keep their method names; only their wire codec changes. */
export const packagedViewOperations = {
  'get-resource': 'get',
  query: 'query',
  commit: 'patch',
  search: 'search',
  'get-context': 'context',
  navigate: 'navigate',
  'pick-resource': 'pickResource',
  'pick-file': 'pickFile',
  subscribe: 'subscribe',
  unsubscribe: 'unsubscribe',
} as const satisfies Record<string, ViewOperation>;
