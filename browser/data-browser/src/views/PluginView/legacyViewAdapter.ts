import {
  isViewKeyEvent,
  isViewRequest,
  packagedViewOperations,
  type ViewRequest,
} from '@tomic/plugin';
import { parseViewQuery, runViewQuery } from '@helpers/extensions/viewQuery';
import { ViewChanges } from '@helpers/extensions/viewApply';
import { parseViewSearch, runViewSearch } from '@helpers/extensions/viewSearch';
import { viewSession } from '@helpers/extensions/viewSession';
import { canViewAccess, type ViewPolicy } from '@helpers/extensions/viewPolicy';
// @wc-ignore-file
import {
  FrameBridge,
  type ColorScheme,
  type FrameSession,
} from '@helpers/extensions/FrameBridge';
import {
  Client,
  core,
  server,
  type JSONArray,
  type JSONValue,
  type ApplyHost,
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
  /**
   * The host UI drive apps get (`store.ui`): answers a UI ask and returns
   * true, or returns false when the request is not one.
   */
  handleUI?: (
    request: { id: string | number; op: string } & Record<string, unknown>,
    post: (reply: { result?: unknown; error?: string }) => void,
  ) => boolean;
  /** Passes a key the frame did not handle to the host's shortcuts. */
  forwardKey?: (message: unknown) => boolean;
}

/**
 * Ops a packaged view answers on the `store` API that have no legacy message
 * type. Pickers stay on the legacy path: those already answer with the
 * resource, which old plugins rely on and `store.ui` reduces to its subject.
 */
const STORE_OPS = new Set([
  'create',
  'save',
  'destroy',
  'query',
  'search',
  'apply',
  'undo',
]);
const LEGACY_PICKERS = new Set(['pickResource', 'pickFile']);

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
  public handleUI: ConstructorArgs['handleUI'];
  public forwardKey: ConstructorArgs['forwardKey'];

  private bridge: FrameBridge;
  /** This frame's `apply` and `undo` history. */
  private changes: ViewChanges;

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
    handleUI,
    forwardKey,
  }: ConstructorArgs) {
    this.handleUI = handleUI;
    this.forwardKey = forwardKey;
    this.changes = new ViewChanges(store, {
      authorize: async subject => {
        const target = await this.store.getResource(subject);

        if (target.hasClasses(server.classes.plugin))
          throw new Error('Plugin cannot edit plugin resources');

        await this.ensureWrite(subject);
      },
      writes: storeWrites(store),
    });
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
      if (isViewKeyEvent(data)) {
        this.forwardKey?.(data);

        return;
      }

      const canonical = isViewRequest(data);
      const session = canonical
        ? viewSession(originalSession, data.id)
        : originalSession;

      if (canonical && !LEGACY_PICKERS.has(data.op)) {
        const request = { ...data.args, id: data.id, op: data.op };

        if (this.handleUI?.(request, session.post)) return;

        if (STORE_OPS.has(data.op)) {
          void this.handleStoreOp(data, session.post).catch(error =>
            session.post({ error: String(error?.message ?? error) }),
          );

          return;
        }
      }

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
  public setStyle(css: string, colorScheme?: ColorScheme): void {
    this.bridge.setStyle(css, colorScheme);
  }

  /** Whether this view may write `subject` without asking the person. */
  public async mayWrite(subject: string): Promise<boolean> {
    if (await canViewAccess(this.store, subject, this.policy, 'write'))
      return true;

    return this.grants().includes('edit-schema') && this.inSchema(subject);
  }

  private grants(): string[] {
    const grants = this.pluginResource.get(server.properties.grants);

    return Array.isArray(grants) ? grants.map(String) : [];
  }

  /**
   * Whether `subject` is part of the schema of what this view shows: one of
   * its classes, a property they list, or something in their ontology. A
   * class that sits in no ontology (directly in a drive) grants only itself
   * and its properties, never the drive around it.
   */
  private async inSchema(subject: string): Promise<boolean> {
    const scope = await schemaScope(this.store, this.context.resource);
    let current: string | undefined = subject;

    for (let depth = 0; current && depth < 12; depth++) {
      if (scope.has(current)) return true;
      const resource: Resource = await this.store.getResource(current);
      const parent: unknown = resource.get(core.properties.parent);
      current = typeof parent === 'string' ? parent : undefined;
    }

    return false;
  }

  /**
   * The `store` calls drive apps make, answered for a packaged view: the
   * same arguments and results, under this view's own rules. Reads and writes
   * outside its grants ask the person, as the legacy calls always have.
   */
  private async handleStoreOp(
    request: ViewRequest,
    post: (reply: { result?: unknown; error?: string }) => void,
  ): Promise<void> {
    const args = request.args;

    switch (request.op) {
      case 'apply':
        if (makesPlugin(args.intents))
          throw new Error('Plugin cannot create plugin resources');

        post({ result: await this.changes.apply(args.intents) });

        return;

      case 'undo':
        post({ result: await this.changes.undo() });

        return;

      case 'create': {
        const parent =
          typeof args.parent === 'string'
            ? args.parent
            : this.context.resource.subject;
        await this.ensureWrite(parent);
        const isA = Array.isArray(args.isA)
          ? args.isA.filter((c): c is string => typeof c === 'string')
          : [];

        if (isA.includes(server.classes.plugin))
          throw new Error('Plugin cannot create plugin resources');

        const resource = await this.store.newResource({
          parent,
          isA,
          propVals: (args.propVals ?? {}) as Record<string, JSONValue>,
        });
        await resource.save();
        post({ result: resourceToUIPluginResource(resource) });

        return;
      }

      case 'save':

      case 'destroy': {
        const subject = String(args.subject ?? '');
        const resource = await this.store.getResource(subject);
        const set = (args.propVals ?? {}) as Record<string, JSONValue>;
        const commit: PluginCommit =
          request.op === 'destroy'
            ? { subject, destroy: true }
            : {
                subject,
                set,
                remove: Array.isArray(args.remove)
                  ? args.remove.filter(
                      (p): p is string => typeof p === 'string',
                    )
                  : undefined,
              };

        if (this.commitChangesPlugin(commit, resource))
          throw new Error('Plugin cannot edit plugin resources');

        await this.ensureWrite(subject);

        for (const [key, value] of Object.entries(commit.set ?? {}))
          await resource.set(key, value as JSONValue);

        for (const key of commit.remove ?? []) resource.remove(key);

        if (commit.destroy) await resource.destroy();
        else await resource.save();

        post({ result: { subject } });

        return;
      }

      case 'query':
        post({
          result: await this.readable(
            await runViewQuery(this.store, parseViewQuery(args)),
          ),
        });

        return;

      case 'search':
        post({
          result: await this.readable(
            await runViewSearch(this.store, parseViewSearch(args)),
          ),
        });

        return;
    }
  }

  /**
   * Only what this view may read. A list of subjects is still data: it says
   * what exists. Members it may not read are left out, not asked about.
   */
  private async readable(subjects: string[]): Promise<string[]> {
    const allowed = await Promise.all(
      subjects.map(async subject => {
        const resource = await this.store.getResource(subject);

        return (
          this.hasReadPermission(subject) ||
          (await this.canPluginReadResource(resource).catch(() => false))
        );
      }),
    );

    return subjects.filter((_, i) => allowed[i]);
  }

  private async ensureWrite(subject: string): Promise<void> {
    if (await this.mayWrite(subject)) return;

    if (!(await this.requestWritePermission(subject)))
      throw new Error('Plugin does not have access to this resource.');
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

/** Writes signed by the person, as every other packaged-view write is. */
function storeWrites(store: Store): ApplyHost {
  return {
    create: async ({ parent, isA, propVals }) => {
      const resource = await store.newResource({ parent, isA, propVals });
      await resource.save();

      return resource.subject;
    },
    set: async (subject, propVals) => {
      const resource = await store.getResource(subject);

      for (const [property, value] of Object.entries(propVals))
        await resource.set(property, value);

      await resource.save();
    },
    remove: async (subject, properties) => {
      const resource = await store.getResource(subject);
      properties.forEach(property => resource.remove(property));
      await resource.save();
    },
    destroy: async subject => {
      await (await store.getResource(subject)).destroy();
    },
  };
}

/** Whether any intent would make something a plugin. */
function makesPlugin(intents: unknown): boolean {
  if (!Array.isArray(intents)) return false;

  return intents.some(intent => {
    const values = (intent as { set?: Record<string, unknown> })?.set;
    const isA = [
      ...((intent as { isA?: unknown[] })?.isA ?? []),
      ...((values?.[core.properties.isA] as unknown[] | undefined) ?? []),
    ];

    return isA.includes(server.classes.plugin);
  });
}

/** The classes a page is, or holds as rows, with their properties and ontologies. */
async function schemaScope(
  store: Store,
  page: { subject: string; props: Record<string, JSONValue> },
): Promise<Set<string>> {
  const isA = page.props[core.properties.isA];
  const rows = page.props[core.properties.classtype];
  const classes = [
    ...(Array.isArray(isA) ? isA : []),
    ...(typeof rows === 'string' ? [rows] : []),
  ].filter((c): c is string => typeof c === 'string');
  const scope = new Set<string>();

  for (const subject of classes) {
    const cls = await store.getResource(subject);

    if (cls.error) continue;
    scope.add(subject);

    for (const property of [
      ...cls.getSubjects(core.properties.requires),
      ...cls.getSubjects(core.properties.recommends),
    ])
      scope.add(property);

    const parent = cls.get(core.properties.parent);

    if (typeof parent === 'string') {
      const ontology = await store.getResource(parent);
      if (ontology.hasClasses(core.classes.ontology)) scope.add(parent);
    }
  }

  return scope;
}
