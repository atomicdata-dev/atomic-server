/**
 * The data API a view gets, and the only one it should need.
 *
 * Shaped after `Store` and `Resource` from `@tomic/lib` on purpose. An author
 * — usually a model that has read the Atomic docs and nothing about this file
 * — should be able to write `store.getResource(...)`, `resource.set(...)`,
 * `resource.save()` and have it work. The postMessage traffic underneath is a
 * transport, not a second vocabulary to learn.
 *
 * Served to the plugin iframe by `/plugin-ui?format=client`. Plain JS with no
 * build step, for the same reason the plugin itself has none.
 */

let nextId = 0;
const pending = new Map();

window.addEventListener('message', event => {
  const message = event.data;

  if (!message || message.id === undefined) return;

  const settle = pending.get(message.id);

  if (!settle) return;

  pending.delete(message.id);

  if (message.error) {
    settle.reject(new Error(message.error));
  } else {
    settle.resolve(message.result);
  }
});

function send(op, payload) {
  const id = ++nextId;

  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    window.parent.postMessage({ __atomic: true, id, op, ...payload }, '*');

    // A host that never answers would otherwise leave the plugin waiting
    // forever with no way to tell that from a slow query.
    setTimeout(() => {
      if (pending.delete(id)) {
        reject(new Error(`The host did not answer ${op} in time.`));
      }
    }, 15000);
  });
}

/**
 * A resource, buffered locally.
 *
 * `set` stages; `save` sends. Same shape as `@tomic/lib`, and the same reason:
 * a write per keystroke is a commit per keystroke.
 */
function makeResource(subject, propVals) {
  const props = { ...propVals };
  let destroyed = false;

  return {
    subject,
    get props() {
      return { ...props };
    },
    get(property) {
      return props[property];
    },
    set(property, value) {
      props[property] = value;

      return this;
    },
    remove(property) {
      delete props[property];

      return this;
    },
    async save() {
      if (destroyed) throw new Error('This resource was destroyed.');

      await send('save', { subject, propVals: props });

      return this;
    },
    async destroy() {
      await send('destroy', { subject });
      destroyed = true;
    },
  };
}

export const store = {
  /** The app this view belongs to. Its own data lives under here. */
  async getApp() {
    return send('app', {});
  },

  /**
   * The table this app's rows live in, and the class they are.
   *
   * A table rather than a folder, so the same rows are sortable, filterable
   * and editable outside the app without the app implementing any of that.
   * Create rows with this as their parent and class and they show up in both.
   */
  async getData() {
    return send('data', {});
  },

  async getResource(subject) {
    const result = await send('get', { subject });

    return makeResource(result.subject, result.propVals);
  },

  /** Subjects matching a property/value pair, scoped to this drive. */
  async query({ property, value }) {
    return send('query', { property, value });
  },

  /**
   * Creates a resource. `parent` defaults to the app, which is the one place
   * a view may always write.
   */
  async newResource({ parent, isA = [], propVals = {} } = {}) {
    const result = await send('create', { parent, isA, propVals });

    return makeResource(result.subject, result.propVals);
  },

  /**
   * Calls back whenever `subject` changes, until the returned function runs.
   *
   * Writing from inside the handler can feed itself: adding a child counts as
   * a change to its parent, so a view that subscribes to its app and writes
   * into it on every notification will keep going. Guard on what actually
   * changed, or write somewhere you are not watching.
   */
  subscribe(subject, handler) {
    const listener = event => {
      if (event.data && event.data.__atomicChanged === subject) handler();
    };

    window.addEventListener('message', listener);
    void send('subscribe', { subject });

    return () => {
      window.removeEventListener('message', listener);
      void send('unsubscribe', { subject });
    };
  },
};
