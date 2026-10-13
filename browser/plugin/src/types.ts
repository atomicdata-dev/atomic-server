export type JSONPrimitive = string | number | boolean;
export type JSONValue = JSONPrimitive | JSONObject | JSONArray | undefined;
export type JSONObject = { [key: string]: JSONValue };
export type JSONArray = Array<JSONValue>;

export interface Resource {
  subject: string;
  title: string;
  loading: boolean;
  props: Record<string, JSONValue>;
}

export interface Commit {
  subject: string;
  set?: Record<string, JSONValue>;
  push?: Record<string, unknown[]>;
  remove?: string[];
  destroy?: boolean;
}

export enum MessageType {
  GET_RESOURCE = 'get-resource',
  QUERY = 'query',
  COMMIT = 'commit',
  SEARCH = 'search',
  GET_CONTEXT = 'get-context',
  NAVIGATE = 'navigate',
  PICK_RESOURCE = 'pick-resource',
  PICK_FILE = 'pick-file',
  SUBSCRIBE = 'subscribe',
  UNSUBSCRIBE = 'unsubscribe',
}

export type PickResourceArgs = {
  isA?: string;
  scope?: string;
  message?: string;
  title?: string;
};

export type PickFileArgs = {
  allowedMimes?: string[];
};

export type ServerResponse = {
  type: 'response';
  requestId: string;
  data: unknown;
};

export type ResourceNotification = {
  type: 'resource-notification';
  resource: Resource;
};

export type ErrorResponse = {
  type: 'error';
  requestId: string;
  error: string;
  message?: string;
};

export type ServerMessage =
  | ServerResponse
  | ResourceNotification
  | ErrorResponse;

export type MessageArgs = {
  [MessageType.GET_RESOURCE]: {
    subject: string;
  };
  [MessageType.QUERY]: {
    property: string;
    value: string;
  };
  [MessageType.COMMIT]: {
    commit: unknown;
  };

  [MessageType.SEARCH]: {
    query: string;
  };
  [MessageType.GET_CONTEXT]: undefined;
  [MessageType.NAVIGATE]: {
    subject: string;
  };
  [MessageType.PICK_RESOURCE]: PickResourceArgs;
  [MessageType.PICK_FILE]: PickFileArgs;
  [MessageType.SUBSCRIBE]: {
    subject: string;
  };
  [MessageType.UNSUBSCRIBE]: {
    subject: string;
  };
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export interface RPCMessage<T extends MessageType = any, A = MessageArgs[T]> {
  type: MessageType;
  args: A;
  requestId: string;
}

/**
 * One entry of `store.getMany(subjects)` in an app frame, in the order asked:
 * the resource, or why it could not be read.
 */
export type GetManyEntry =
  | (Resource & { error?: undefined })
  | { subject: string; error: string };

/** Whether the host is drawn light or dark. */
export type ColorScheme = 'light' | 'dark';

/**
 * The theme message a host posts to a view frame on load and whenever its
 * theme changes. `css` sets the `--t-*` variables (including
 * `--t-color-success`) and `color-scheme` on `:root`; `colorScheme` is the
 * host's actual setting, so a view need not guess it from a background
 * colour. In an app frame, `store.getTheme()` and `store.onThemeChange()`
 * read it.
 */
export interface ThemeMessage {
  type: '__atomic_style';
  css: string;
  colorScheme?: ColorScheme;
}

export interface PageContext {
  /** The current page resource */
  resource: Resource;
  /** Subject of the user's agent */
  agent?: string;
}
