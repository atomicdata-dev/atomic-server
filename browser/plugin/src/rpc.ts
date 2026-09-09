import { viewRequest, packagedViewOperations } from './viewProtocol';
import {
  MessageType,
  type Commit,
  type ErrorResponse,
  type MessageArgs,
  type PageContext,
  type Resource,
  type ServerMessage,
} from './types';

type ResourceCallback = (resource: Resource) => void;

export class RPCClient {
  private requests: Map<
    string,
    [(results: unknown) => void, (error: ErrorResponse) => void]
  > = new Map();
  private subscriptions: Map<string, ResourceCallback[]> = new Map();

  constructor() {
    window.addEventListener('message', (event: MessageEvent) => {
      if (
        event.source !== window.parent ||
        !event.data ||
        typeof event.data !== 'object'
      )
        return;
      const wire = event.data;
      const data =
        wire.type === 'atomic.view.response' && wire.version === 1
          ? wire.error !== undefined
            ? { type: 'error', requestId: wire.id, error: wire.error }
            : { type: 'response', requestId: wire.id, data: wire.result }
          : wire.type === 'atomic.view.change' && wire.version === 1
            ? { type: 'resource-notification', resource: wire.resource }
            : wire;
      const e = { data: data as ServerMessage };
      if (e.data.type === 'resource-notification' && !e.data.resource) return;

      if (e.data.type === 'resource-notification') {
        const callbacks = this.subscriptions.get(e.data.resource.subject) ?? [];

        for (const cb of callbacks) {
          cb(e.data.resource);
        }

        return;
      }

      if (!this.requests.has(e.data.requestId)) {
        return;
      }

      const [onSuccess, onError] = this.requests.get(e.data.requestId)!;

      if (e.data.type === 'error') {
        onError(e.data);

        return;
      }

      if (e.data.type === 'response') {
        onSuccess(e.data.data);

        return;
      }

      onError({
        type: 'error',
        requestId: (e.data as ErrorResponse).requestId,
        error: 'unknown-server-message-type',
        message: 'Unknown server message type',
      });
    });
  }

  /** Fetches a resource from the host */
  public getResource(subject: string): Promise<Resource> {
    return this.callFunction(MessageType.GET_RESOURCE, {
      subject,
    }) as Promise<Resource>;
  }

  public query(property: string, value: string): Promise<Resource[]> {
    return this.callFunction(MessageType.QUERY, { property, value }) as Promise<
      Resource[]
    >;
  }

  public commit(commit: Commit): Promise<{ success: true }> {
    return this.callFunction(MessageType.COMMIT, { commit }) as Promise<{
      success: true;
    }>;
  }

  /** Returns the current page context */
  public getPageContext(): Promise<PageContext> {
    return this.callFunction(
      MessageType.GET_CONTEXT,
      undefined,
    ) as Promise<PageContext>;
  }

  /**
   * Opens a resource picker dialog, will resolve once the user has picked a resource
   * You can provide a title and message to display in the dialog.
   * You can also restrict what kind of resources can be selected and the scope to search in.
   */
  public pickResource(
    options: {
      isA?: string;
      scope?: string;
      message?: string;
      title?: string;
    } = {},
  ): Promise<Resource | undefined> {
    return this.callFunction(MessageType.PICK_RESOURCE, options) as Promise<
      Resource | undefined
    >;
  }

  /**
   * Opens a file picker dialog where the user can select existing files on their AtomicServer or upload a new file.
   * Resolves with the subject of the selected file or undefined if the user cancels the dialog.
   * You can restrict the allowed mime types of the files that can be selected.
   */
  public pickFile(
    args: {
      allowedMimes?: string[];
    } = {},
  ): Promise<Resource | undefined> {
    return this.callFunction(MessageType.PICK_FILE, args) as Promise<
      Resource | undefined
    >;
  }

  /**
   * Navigate the page to a resource
   */
  public navigate(subject: string): Promise<boolean> {
    return this.callFunction(MessageType.NAVIGATE, {
      subject,
    }) as Promise<boolean>;
  }

  public subscribe(
    subject: string,
    callback: (resource: Resource) => void,
  ): () => void {
    let callbacks = this.subscriptions.get(subject) ?? [];
    callbacks.push(callback);
    this.subscriptions.set(subject, callbacks);
    this.callFunction(MessageType.SUBSCRIBE, {
      subject,
    });

    return () => {
      callbacks = callbacks.filter(cb => cb !== callback);

      if (callbacks.length === 0) {
        this.callFunction(MessageType.UNSUBSCRIBE, {
          subject,
        });
      }

      this.subscriptions.set(subject, callbacks);
    };
  }

  private callFunction<T extends MessageType>(
    messageType: T,
    args: MessageArgs[T],
  ) {
    return new Promise((resolve, reject) => {
      const requestId = crypto.randomUUID();
      this.requests.set(requestId, [
        (result: unknown) => {
          this.requests.delete(requestId);
          resolve(result);
        },
        (error: ErrorResponse) => {
          this.requests.delete(requestId);
          reject(new Error(error.message ?? error.error));
        },
      ]);

      window.parent.postMessage(
        viewRequest(
          requestId,
          packagedViewOperations[messageType],
          (args ?? {}) as Record<string, unknown>,
        ),
        '*',
      );
    });
  }
}
