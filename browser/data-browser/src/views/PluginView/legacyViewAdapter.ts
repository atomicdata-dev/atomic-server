import { isViewRequest, packagedViewOperations } from '@tomic/plugin';
import { viewSession } from '@helpers/extensions/viewSession';
import { canViewAccess, type ViewPolicy } from '@helpers/extensions/viewPolicy';
// @wc-ignore-file
import {
  FrameBridge,
  type FrameSession,
} from '@helpers/extensions/FrameBridge';
import {
  Client,
  core,
  server,
  type JSONArray,
  type JSONValue,
  type Resource,
  type Store,
} from '@tomic/react';
import {
  MessageType,
  type PageContext,
  type RPCMessage,
  type Resource as UIPluginResource,
  type Commit as PluginCommit,
} from '@tomic/plugin';
import type { PickResourceFn } from './useResourcePicker';
import type { PickFileFn } from './useFilePicker';
import type { RequestPermissionFn } from './useRequestPermissionDialog';

type Request<T extends MessageType = MessageType> = T extends MessageType
  ? RPCMessage<T> & { type: T; session: FrameSession }
  : never;

interface ConstructorArgs {
  context: PageContext;
  store: Store;
  iFrame: HTMLIFrameElement;
  pluginResource: Resource;
  navigate: (subject: string) => void;
  pickResource: PickResourceFn;
  pickFile: PickFileFn;
  requestReadPermission: RequestPermissionFn;
  hasReadPermission: (subject: string) => boolean;
  requestWritePermission: RequestPermissionFn;
}

export class LegacyViewAdapter {
  public context: PageContext;
  public store: Store;
  public iFrame: HTMLIFrameElement;
  public navigate: (subject: string) => void;
  public pickResource: PickResourceFn;
  public pickFile: PickFileFn;
  public requestReadPermission: RequestPermissionFn;
  public hasReadPermission: (subject: string) => boolean;
  public requestWritePermission: RequestPermissionFn;

  public pluginResource: Resource;

  private bridge: FrameBridge;

  constructor({
    context,
    store,
    iFrame,
    pluginResource,
    navigate,
    pickResource,
    pickFile,
    requestReadPermission,
    hasReadPermission,
    requestWritePermission,
  }: ConstructorArgs) {
    this.context = context;
    this.store = store;
    this.iFrame = iFrame;
    this.pluginResource = pluginResource;
    this.navigate = navigate;
    this.pickResource = pickResource;
    this.pickFile = pickFile;
    this.requestReadPermission = requestReadPermission;
    this.hasReadPermission = hasReadPermission;
    this.requestWritePermission = requestWritePermission;
    this.bridge = new FrameBridge(iFrame, (data, originalSession) => {
      const canonical = isViewRequest(data);
      const session = canonical
        ? viewSession(originalSession, data.id)
        : originalSession;
      const type = canonical
        ? Object.keys(packagedViewOperations).find(
            key => packagedViewOperations[key as MessageType] === data.op,
          )
        : undefined;

      if (canonical && !type) {
        session.post({
          error: /* @wc-ignore */ 'This view does not support that operation',
        });

        return;
      }

      const message = (
        canonical ? { type, args: data.args, requestId: String(data.id) } : data
      ) as Partial<RPCMessage>;
      if (
        typeof message.type !== 'string' ||
        typeof message.requestId !== 'string'
      )
        return;
      const request = { ...message, session } as Request;
      void this.handleMessage(request).catch(error =>
        this.sendError(request, 'request-failed', String(error)),
      );
    });
  }

  public stopServer(): void {
    this.bridge.close();
  }
  public setStyle(css: string): void {
    this.bridge.setStyle(css);
  }

  private async handleMessage(message: Request): Promise<void> {
    switch (message.type) {
      case MessageType.GET_RESOURCE:
        await this.handleGetResource(message);
        break;
      case MessageType.QUERY:
        await this.handleQuery(message);
        break;
      case MessageType.COMMIT:
        await this.handleCommit(message);
        break;
      case MessageType.SEARCH:
        await this.handleSearch(message);
        break;
      case MessageType.GET_CONTEXT:
        await this.handleGetContext(message);
        break;
      case MessageType.NAVIGATE:
        await this.handleNavigate(message);
        break;
      case MessageType.PICK_RESOURCE:
        await this.handlePickResource(message);
        break;
      case MessageType.PICK_FILE:
        await this.handlePickFile(message);
        break;
      case MessageType.SUBSCRIBE:
        await this.handleSubscribe(message);
        break;
      case MessageType.UNSUBSCRIBE:
        await this.handleUnsubscribe(message);
        break;
      default:
        this.sendResponse(message, 'UNSUPPORTED MESSAGE');
    }
  }

  private async handleGetResource(
    message: Request<MessageType.GET_RESOURCE>,
  ): Promise<void> {
    const resource = await this.store.getResource(message.args.subject);

    if (!(await this.canPluginReadResource(resource))) {
      const allowed = await this.requestReadPermission(message.args.subject);

      if (!allowed) {
        this.sendError(
          message,
          'unauthorized',
          /* @wc-ignore */ 'Plugin does not have access to this resource.',
        );

        return;
      }
    }

    this.sendResponse(message, resourceToUIPluginResource(resource));
  }

  private async handleQuery(
    message: Request<MessageType.QUERY>,
  ): Promise<void> {
    this.sendError(
      message,
      'unsupported-operation',
      /* @wc-ignore */ 'Query is not supported by packaged views',
    );
  }

  private async handleCommit(
    message: Request<MessageType.COMMIT>,
  ): Promise<void> {
    const { commit } = message.args as { commit: PluginCommit };

    if (!commit || !commit.subject) {
      this.sendError(
        message,
        'invalid-args',
        /* @wc-ignore */ 'Commit subject is missing',
      );

      return;
    }

    const resource = await this.store.getResource(commit.subject);

    if (this.commitChangesPlugin(commit, resource)) {
      this.sendError(
        message,
        'unauthorized',
        /* @wc-ignore */ 'Plugin cannot edit plugin resources',
      );

      return;
    }

    if (!(await this.canPluginWriteResource(resource))) {
      const allowed = await this.requestWritePermission(commit.subject);

      if (!allowed) {
        this.sendError(
          message,
          'unauthorized',
          /* @wc-ignore */ 'Plugin does not have access to this resource.',
        );

        return;
      }
    }

    if (!message.session.isActive()) return;

    try {
      if (commit.set) {
        for (const [key, value] of Object.entries(commit.set)) {
          await resource.set(key, value as JSONValue);
        }
      }

      if (commit.remove) {
        for (const key of commit.remove as string[]) {
          resource.remove(key);
        }
      }

      if (commit.destroy) {
        await resource.destroy();
      } else {
        await resource.save();
      }

      this.sendResponse(message, { success: true });
    } catch (e) {
      this.sendError(message, 'commit-failed', e.message);
    }
  }

  private async handleSearch(
    message: Request<MessageType.SEARCH>,
  ): Promise<void> {
    this.sendError(
      message,
      'unsupported-operation',
      /* @wc-ignore */ 'Search is not supported by packaged views',
    );
  }

  private async handleGetContext(
    message: Request<MessageType.GET_CONTEXT>,
  ): Promise<void> {
    this.sendResponse(message, this.context);
  }

  private async handleNavigate(
    message: Request<MessageType.NAVIGATE>,
  ): Promise<void> {
    if (!Client.isValidSubject(message.args.subject)) {
      this.sendResponse(message, false);

      return;
    }

    this.sendResponse(message, true);
    this.navigate(message.args.subject);
  }

  private async handlePickResource(
    message: Request<MessageType.PICK_RESOURCE>,
  ): Promise<void> {
    const selected = await this.pickResource(message.args);

    if (!selected) {
      this.sendResponse(message, undefined);

      return;
    }

    const resource = await this.store.getResource(selected);

    this.sendResponse(message, resourceToUIPluginResource(resource));
  }

  private async handlePickFile(
    message: Request<MessageType.PICK_FILE>,
  ): Promise<void> {
    const selected = await this.pickFile(message.args);

    if (!selected) {
      this.sendResponse(message, undefined);

      return;
    }

    const resource = await this.store.getResource(selected);

    this.sendResponse(message, resourceToUIPluginResource(resource));
  }

  private async handleSubscribe(
    message: Request<MessageType.SUBSCRIBE>,
  ): Promise<void> {
    const r = await this.store.getResource(message.args.subject);

    if (!(await this.canPluginReadResource(r))) {
      const allowed = await this.requestReadPermission(message.args.subject);

      if (!allowed) {
        this.sendResponse(message, false);

        return;
      }
    }

    const subject = message.args.subject;
    message.session.watch(subject, () =>
      this.store.subscribe(subject, resource => {
        // A notification contains data. Recheck the grant instead of treating a
        // successful subscription as permanent authorization.
        void this.canPluginReadResource(resource)
          .then(allowed => {
            if (!allowed && !this.hasReadPermission(subject)) {
              message.session.unwatch(subject);

              return;
            }

            message.session.post({
              type: 'resource-notification',
              resource: resourceToUIPluginResource(resource),
            });
          })
          .catch(() => message.session.unwatch(subject));
      }),
    );
    this.sendResponse(message, true);
  }

  private async handleUnsubscribe(
    message: Request<MessageType.UNSUBSCRIBE>,
  ): Promise<void> {
    message.session.unwatch(message.args.subject);
    this.sendResponse(message, true);
  }

  private sendResponse(message: Request, data: unknown): void {
    message.session.post({
      type: 'response',
      requestId: message.requestId,
      data,
    });
  }

  private sendError(
    message: Request,
    error: string,
    errorMessage?: string,
  ): void {
    message.session.post({
      type: 'error',
      requestId: message.requestId,
      error,
      message: errorMessage,
    });
  }

  private get policy(): ViewPolicy {
    return {
      kind: 'packaged',
      root: this.context.resource.subject,
      classes:
        (this.context.resource.props[core.properties.isA] as string[]) ?? [],
      agent: this.pluginResource.get(server.properties.pluginAgent),
    };
  }

  private canPluginReadResource(resource: Resource): Promise<boolean> {
    return canViewAccess(this.store, resource.subject, this.policy, 'read');
  }

  private canPluginWriteResource(resource: Resource): Promise<boolean> {
    return canViewAccess(this.store, resource.subject, this.policy, 'write');
  }

  /**
   * Check if the commit changes a plugin resource to prevent plugins from updating themselves or other plugins.
   */
  private commitChangesPlugin(
    commit: PluginCommit,
    resource: Resource,
  ): boolean {
    if (resource.hasClasses(server.classes.plugin)) {
      return true;
    }

    if (
      commit.set &&
      Array.isArray(commit.set[core.properties.isA]) &&
      (commit.set[core.properties.isA] as JSONArray).includes(
        server.classes.plugin,
      )
    ) {
      return true;
    }

    if (
      commit.push &&
      Array.isArray(commit.push[core.properties.isA]) &&
      (commit.push[core.properties.isA] as JSONArray).includes(
        server.classes.plugin,
      )
    ) {
      return true;
    }

    return false;
  }
}

export function resourceToUIPluginResource(
  resource: Resource,
): UIPluginResource {
  return {
    subject: resource.subject,
    title: resource.title,
    loading: false,
    props: entriesToJSONRecord(resource.getEntries()),
  };
}

function entriesToJSONRecord(
  entries: [string, unknown][],
): Record<string, JSONValue> {
  return Object.fromEntries(
    entries.map(([key, value]) => {
      if (value instanceof Uint8Array) {
        return [key, undefined];
      }

      return [key, value as JSONValue];
    }),
  ) as Record<string, JSONValue>;
}
