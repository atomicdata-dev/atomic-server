/** Versioned UI wire contract. Authority comes from the host's view instance. */
export const VIEW_PROTOCOL_VERSION = 1;
export type ViewOperation =
  | 'app'
  | 'data'
  | 'get'
  /** Up to 100 `get`s in one round trip; per-subject errors in place. */
  | 'getMany'
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
  | 'unsubscribe'
  /**
   * A capability for one integration-proxy connection, bound to the frame's
   * own public key and signed by the user (ontola/atomic-plugins#54).
   */
  | 'proxyCapability'
  /** Connection references (never credentials) delegated to this app. */
  | 'proxyConnections'
  /** Ask the person, in host UI, to connect a proxy platform for this app. */
  | 'proxyConnect'
  /**
   * Host UI. The host draws these itself: a frame cannot draw outside its own
   * box, and a share dialog or a confirm should look like the host's own.
   */
  | 'confirm'
  | 'toast'
  | 'menu'
  | 'resourceMenu'
  | 'share'
  | 'openResource'
  | 'environment'
  /** Atomic's own form for a new resource of a class. */
  | 'form'
  /** Several writes as one change, in the intent format `run()` returns. */
  | 'apply'
  /** Reverts the view's latest `apply`. */
  | 'undo';
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
      'getMany',
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
      'proxyCapability',
      'proxyConnections',
      'proxyConnect',
      'confirm',
      'toast',
      'menu',
      'resourceMenu',
      'share',
      'openResource',
      'environment',
      'form',
      'apply',
      'undo',
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

/**
 * A key press the view did not handle, passed up so the host's own shortcuts
 * (search, undo, Escape) keep working while focus is inside the frame.
 * A notification: the host does not answer it.
 */
export interface ViewKeyEvent {
  type: 'atomic.view.key';
  version: 1;
  key: string;
  code: string;
  ctrlKey: boolean;
  metaKey: boolean;
  shiftKey: boolean;
  altKey: boolean;
}

export function isViewKeyEvent(value: unknown): value is ViewKeyEvent {
  if (!value || typeof value !== 'object') return false;
  const event = value as ViewKeyEvent;

  return (
    event.type === 'atomic.view.key' &&
    event.version === 1 &&
    typeof event.key === 'string' &&
    event.key.length > 0 &&
    event.key.length <= 32 &&
    typeof event.code === 'string' &&
    event.code.length <= 32 &&
    typeof event.ctrlKey === 'boolean' &&
    typeof event.metaKey === 'boolean' &&
    typeof event.shiftKey === 'boolean' &&
    typeof event.altKey === 'boolean'
  );
}
