import type { Intent } from '@tomic/lib';
import { viewRequest, type ViewOperation } from './viewProtocol';

/**
 * The data API a plugin view gets, shaped after `Store` and `Resource` from
 * `@tomic/lib`: `store.getResource(...)`, `resource.set(...)`,
 * `await resource.save()`. A drive app gets the same object from
 * `/plugin-ui?format=client`, so one API covers both kinds of view.
 *
 * The postMessage traffic underneath is a transport, not a second vocabulary.
 * The host answers with the signed-in person's store and its own rules for
 * what this view may read and write.
 */

export type PropValue =
  | string
  | number
  | boolean
  | null
  | PropValue[]
  | { [key: string]: PropValue };

export interface QueryArgs {
  /** With `value`: members whose `property` is `value`. */
  property?: string;
  value?: string;
  /** More property/value pairs, all of which must match. At most 10. */
  filters?: { property: string; value: string }[];
  sortBy?: string;
  sortDesc?: boolean;
  /** 1 to 100. Only used with `page`. */
  pageSize?: number;
  /** A page from 0. Without it: every member, at most 500. */
  page?: number;
}

export interface SearchArgs {
  /** Only resources of this class. */
  isA?: string;
  /** Only resources under these. */
  parents?: string[];
  /** 1 to 50, default 20. */
  limit?: number;
}

export interface ViewContext {
  /** The resource this view is showing. */
  subject: string;
  /** The signed-in person's agent, when someone is signed in. */
  agent?: string;
}

export type MenuPoint =
  | { x: number; y: number }
  | { clientX: number; clientY: number };

export type MenuItem =
  | 'divider'
  | { id: string; label: string; disabled?: boolean };

/** Requests that wait on the person, so they get no timeout. */
const ASKS_THE_PERSON: ReadonlySet<ViewOperation> = new Set([
  'confirm',
  'menu',
  'share',
  'pickResource',
  'pickFile',
  'form',
  'proxyConnect',
]);

/** How long the host gets for anything else: its own recovery takes 30s. */
const HOST_TIMEOUT_MS = 60_000;

/** A resource, buffered here: `set` stages, `save` sends. */
export class ViewResource {
  private values: Record<string, PropValue>;
  private changed = new Set<string>();
  private removed = new Set<string>();
  private destroyed = false;

  public constructor(
    private readonly store: ViewStore,
    public readonly subject: string,
    public title: string,
    props: Record<string, PropValue>,
  ) {
    this.values = { ...props };
  }

  public get props(): Record<string, PropValue> {
    return { ...this.values };
  }

  public get<T extends PropValue = PropValue>(property: string): T | undefined {
    return this.values[property] as T | undefined;
  }

  /** Stages a value. Returns this resource, so calls chain. */
  public set(property: string, value: PropValue): this {
    this.values[property] = value;
    this.changed.add(property);
    this.removed.delete(property);

    return this;
  }

  public remove(property: string): this {
    delete this.values[property];
    this.changed.delete(property);
    this.removed.add(property);

    return this;
  }

  public getClasses(): string[] {
    const isA = this.values[IS_A];

    return Array.isArray(isA) ? (isA as string[]) : [];
  }

  public hasClasses(...classes: string[]): boolean {
    const own = this.getClasses();

    return classes.every(c => own.includes(c));
  }

  /** Sends what was set and removed since the last save. */
  public async save(): Promise<this> {
    if (this.destroyed) throw new Error('This resource was destroyed.');

    const remove = [...this.removed];
    const propVals = Object.fromEntries(
      [...this.changed].map(p => [p, this.values[p]]),
    );
    await this.store.call('save', {
      subject: this.subject,
      propVals,
      ...(remove.length ? { remove } : {}),
    });
    remove.forEach(p => this.removed.delete(p));
    Object.keys(propVals).forEach(p => this.changed.delete(p));

    return this;
  }

  public async destroy(): Promise<void> {
    await this.store.call('destroy', { subject: this.subject });
    this.destroyed = true;
  }
}

const IS_A = 'https://atomicdata.dev/properties/isA';

interface Pending {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timer?: ReturnType<typeof setTimeout>;
}

/** The view's store. Use the shared `store` export; one per frame is enough. */
export class ViewStore {
  private pending = new Map<string, Pending>();
  private watchers = new Map<string, Set<(resource: ViewResource) => void>>();
  private listening = false;

  /** Fetches a resource the host lets this view read. */
  public async getResource(subject: string): Promise<ViewResource> {
    return this.toResource(await this.call('get', { subject }));
  }

  /**
   * Creates a resource and saves it. `parent` defaults to where this view may
   * always write: the app for a drive app, the page for a packaged view.
   */
  public async newResource({
    parent,
    isA = [],
    propVals = {},
  }: {
    parent?: string;
    isA?: string[];
    propVals?: Record<string, PropValue>;
  } = {}): Promise<ViewResource> {
    return this.toResource(
      await this.call('create', { parent, isA, propVals }),
    );
  }

  /** Subjects of a collection, like `CollectionBuilder` builds. */
  public query(args: QueryArgs): Promise<string[]> {
    return this.call('query', { ...args });
  }

  /** Full-text search, as the signed-in person would find things. */
  public search(text: string, args: SearchArgs = {}): Promise<string[]> {
    return this.call('search', { text, ...args });
  }

  /** What this view is showing, and who is looking. */
  public async getContext(): Promise<ViewContext> {
    const context = (await this.call('context', {})) as {
      subject?: string;
      resource?: { subject: string };
      agent?: string;
    };

    return {
      subject: context.subject ?? context.resource?.subject ?? '',
      agent: context.agent || undefined,
    };
  }

  /**
   * Several writes as one change, in the intent format a plugin's `run()`
   * returns. Refer to a resource created in the same call as
   * `local:<localId>`. All of it is checked before anything is written; if a
   * write still fails, the ones before it are rolled back. Resolves to the
   * subjects the creates got, by `localId`. At most 200 intents.
   */
  public apply(
    intents: Intent[],
  ): Promise<{ subjects: Record<string, string> }> {
    return this.call('apply', { intents });
  }

  /**
   * Reverts this view's latest `apply`. False when there is nothing to undo.
   * Rejects, changing nothing, when someone changed those values since.
   */
  public undo(): Promise<boolean> {
    return this.call('undo', {});
  }

  /**
   * Calls back with the fresh resource whenever `subject` changes, until the
   * returned function runs.
   */
  public subscribe(
    subject: string,
    callback: (resource: ViewResource) => void,
  ): () => void {
    this.listen();
    const callbacks = this.watchers.get(subject) ?? new Set();
    const first = callbacks.size === 0;
    callbacks.add(callback);
    this.watchers.set(subject, callbacks);

    if (first) void this.call('subscribe', { subject }).catch(() => undefined);

    return () => {
      callbacks.delete(callback);

      if (callbacks.size === 0) {
        this.watchers.delete(subject);
        void this.call('unsubscribe', { subject }).catch(() => undefined);
      }
    };
  }

  /**
   * Host UI. The page around this frame draws these with Atomic's own
   * components, names this view to the person, and can reach past the
   * frame's edges.
   */
  public readonly ui = {
    /** A yes/no question in a host dialog. */
    confirm: (args: {
      title: string;
      body?: string;
      confirmLabel?: string;
      danger?: boolean;
    }): Promise<boolean> => this.call('confirm', { ...args }),

    /** A short notice in the host's corner. */
    toast: (
      text: string,
      { kind = 'info' }: { kind?: 'success' | 'error' | 'info' } = {},
    ): Promise<true> => this.call('toast', { text, kind }),

    /**
     * A menu at `at`: a point in this frame, or the MouseEvent of a click.
     * Resolves to the chosen item's id, or null when dismissed.
     */
    menu: (args: {
      at: MenuPoint;
      items: MenuItem[];
    }): Promise<string | null> =>
      this.call('menu', { items: args.items, at: toPoint(args.at) }),

    /** Atomic's own menu for a resource, at `at`. */
    resourceMenu: (subject: string, { at }: { at: MenuPoint }): Promise<true> =>
      this.call('resourceMenu', { subject, at: toPoint(at) }),

    /** Atomic's share dialog. Resolves once it is closed. */
    share: (subject: string): Promise<true> => this.call('share', { subject }),

    /** Opens `subject` in the host, leaving this view. */
    openResource: (subject: string): Promise<true> =>
      this.call('openResource', { subject }),

    /**
     * Lets the person search for a resource, optionally of class `isA`.
     * Resolves to its subject, or null when cancelled.
     */
    pickResource: async (
      args: { isA?: string; title?: string } = {},
    ): Promise<string | null> =>
      subjectOf(await this.call('pickResource', { ...args })),

    /**
     * Lets the person choose a file, or upload one. `accept` lists MIME types.
     * Resolves to the file's subject, or null when cancelled.
     */
    pickFile: async (
      args: { accept?: string[] } = {},
    ): Promise<string | null> =>
      subjectOf(
        await this.call('pickFile', {
          accept: args.accept,
          // What a packaged host has always read.
          allowedMimes: args.accept,
        }),
      ),

    /**
     * Atomic's own form for a new resource of `class`, prefilled from
     * `propVals`. The person saves it under `parent`, which must be somewhere
     * this view may write. Resolves to the new subject, or null.
     */
    form: (args: {
      class: string;
      parent?: string;
      propVals?: Record<string, string | number | boolean>;
    }): Promise<string | null> => this.call('form', { ...args }),

    /** The person's language, and where this view is placed. */
    environment: (): Promise<{ locale: string; placement: string }> =>
      this.call('environment', {}),
  };

  /** One request to the host. The transport under every method above. */
  public call<T = never>(
    op: ViewOperation,
    args: Record<string, unknown>,
  ): Promise<T> {
    this.listen();
    const id = crypto.randomUUID();

    return new Promise<T>((resolve, reject) => {
      const timer = ASKS_THE_PERSON.has(op)
        ? undefined
        : setTimeout(() => {
            if (this.pending.delete(id))
              reject(new Error(`The host did not answer ${op} in time.`));
          }, HOST_TIMEOUT_MS);
      this.pending.set(id, {
        resolve: resolve as (value: unknown) => void,
        reject,
        timer,
      });
      window.parent.postMessage(viewRequest(id, op, args), '*');
    });
  }

  private toResource(result: unknown): ViewResource {
    const r = result as {
      subject: string;
      title?: string;
      props?: Record<string, PropValue>;
    };

    return new ViewResource(
      this,
      r.subject,
      r.title ?? r.subject,
      r.props ?? {},
    );
  }

  /** Attached on first use, so importing this module has no side effects. */
  private listen(): void {
    if (this.listening) return;
    this.listening = true;
    forwardUnhandledKeys();

    window.addEventListener('message', (event: MessageEvent) => {
      if (event.source !== window.parent) return;
      const message = event.data;

      if (message?.version !== 1) return;

      if (message.type === 'atomic.view.change') {
        this.notify(message.subject, message.resource);

        return;
      }

      if (message.type !== 'atomic.view.response') return;
      const settle = this.pending.get(message.id);

      if (!settle) return;
      this.pending.delete(message.id);
      clearTimeout(settle.timer);

      if (message.error !== undefined) settle.reject(new Error(message.error));
      else settle.resolve(message.result);
    });
  }

  private notify(subject: unknown, resource: unknown): void {
    if (typeof subject !== 'string') return;
    const callbacks = this.watchers.get(subject);

    if (!callbacks?.size) return;

    // A drive app's host says only what changed; a packaged host sends the
    // resource along. Either way the callback gets a fresh resource.
    const fresh = resource
      ? Promise.resolve(this.toResource(resource))
      : this.getResource(subject);
    void fresh
      .then(r => callbacks.forEach(callback => callback(r)))
      .catch(() => undefined);
  }
}

let forwardingKeys = false;

/**
 * Keys this view did not handle go up to the host, so its shortcuts (search,
 * Escape) keep working while focus is in here. Only Escape and keys held with
 * Ctrl, Cmd or Alt: plain typing stays in this frame. A view that handles a
 * key itself calls `preventDefault()` and the host never sees it.
 */
export function forwardUnhandledKeys(): void {
  if (forwardingKeys || typeof window === 'undefined') return;
  forwardingKeys = true;

  window.addEventListener('keydown', (event: KeyboardEvent) => {
    if (event.defaultPrevented || event.isComposing) return;
    if (
      event.key !== 'Escape' &&
      !event.ctrlKey &&
      !event.metaKey &&
      !event.altKey
    )
      return;

    window.parent.postMessage(
      {
        type: 'atomic.view.key',
        version: 1,
        key: event.key,
        code: event.code,
        ctrlKey: event.ctrlKey,
        metaKey: event.metaKey,
        shiftKey: event.shiftKey,
        altKey: event.altKey,
      },
      '*',
    );
  });
}

export function toPoint(at: MenuPoint): { x: number; y: number } {
  return 'clientX' in at ? { x: at.clientX, y: at.clientY } : at;
}

/** A packaged host answers a pick with the resource, a drive app with its subject. */
function subjectOf(result: unknown): string | null {
  if (typeof result === 'string') return result;

  if (result && typeof result === 'object' && 'subject' in result)
    return String((result as { subject: unknown }).subject);

  return null;
}

/** This frame's store. */
export const store = new ViewStore();
