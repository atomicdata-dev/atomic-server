// @wc-ignore-file
import {
  FrameBridge,
  type FrameSession,
} from '@helpers/extensions/FrameBridge';
import {
  Client,
  core,
  server,
  urls,
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
    this.bridge = new FrameBridge(iFrame, (data, session) => {
      const message = data as Partial<RPCMessage>;
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
    this.sendResponse(message, 'not implemented');
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
    this.sendResponse(message, 'not implemented');
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
  }

  private async handleUnsubscribe(
    message: Request<MessageType.UNSUBSCRIBE>,
  ): Promise<void> {
    message.session.unwatch(message.args.subject);
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

  private async canPluginReadResource(resource: Resource): Promise<boolean> {
    const pluginAgent = this.pluginResource.get(server.properties.pluginAgent);

    const pageSubject = this.context.resource.subject;
    const pageClasses =
      (this.context.resource.props[core.properties.isA] as string[]) ?? [];

    const permittedRoots = [pageSubject, ...pageClasses];

    const canRead = (r: Resource): boolean => {
      if (permittedRoots.includes(r.subject)) {
        return true;
      }

      const parent = r.get(core.properties.parent);

      if (permittedRoots.includes(parent)) {
        return true;
      }

      if (
        r
          .get(core.properties.read)
          ?.some(
            agent =>
              agent === urls.instances.publicAgent || agent === pluginAgent,
          )
      ) {
        return true;
      }

      if (r.get(core.properties.write)?.includes(pluginAgent)) {
        return true;
      }

      return false;
    };

    if (canRead(resource)) {
      return true;
    }

    // Check if the resource is a child of the page resource or if any parent gives the plugin read rights.
    const parents = await this.store.getResourceAncestry(resource);

    for (const parent of parents) {
      const r = await this.store.getResource(parent);

      if (canRead(r)) {
        return true;
      }
    }

    return false;
  }

  private async canPluginWriteResource(resource: Resource): Promise<boolean> {
    const pluginAgent = this.pluginResource.get(server.properties.pluginAgent);

    const canWrite = (r: Resource): boolean => {
      if (r.subject === this.context.resource.subject) {
        return true;
      }

      const parent = r.get(core.properties.parent);

      if (parent === this.context.resource.subject) {
        return true;
      }

      if (r.get(core.properties.write)?.includes(pluginAgent)) {
        return true;
      }

      return false;
    };

    if (resource.subject === this.context.resource.subject) {
      return true;
    }

    if (canWrite(resource)) {
      return true;
    }

    // Check if the resource is a child of the page resource or if any parent gives the plugin write rights.
    const parents = await this.store.getResourceAncestry(resource);

    for (const parent of parents) {
      const r = await this.store.getResource(parent);

      if (canWrite(r)) {
        return true;
      }
    }

    return false;
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
