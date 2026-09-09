import { project } from '../adapter.js';
import { core, dataBrowser } from '../../../browser/lib/src/index.js';

export const digest = async value =>
  Array.from(
    new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)),
    ),
    byte => byte.toString(16).padStart(2, '0'),
  ).join('');
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/** Reuses the GitHub integration mapping with an injected browser proxy transport. */
export class GitHubPort {
  constructor(store, connection, call) {
    this.store = store;
    this.connection = connection;
    this.scope = `https://github.com/${connection.repository}`;
    if (!call)
      throw new Error('A browser integration-proxy transport is required');
    this.call = call;
  }
  async request(action, args, key) {
    const receipt = await this.call(
      action,
      args,
      await digest(key ?? `${action}:${JSON.stringify(args)}`),
    );
    if (receipt.status < 200 || receipt.status >= 300)
      throw new Error(`GitHub ${action} returned ${receipt.status}`);
    return receipt.body ? JSON.parse(receipt.body) : undefined;
  }
  row(entity, raw, context = {}) {
    if (entity === 'issue') {
      if (raw.pull_request) throw new Error('Pull requests are excluded');
      return {
        id: raw.number,
        value: project(raw),
        metadata: this.metadata(raw, { number: raw.number }),
      };
    }
    if (
      !Number.isSafeInteger(raw.id) ||
      raw.id <= 0 ||
      typeof raw.body !== 'string'
    )
      throw new Error('Invalid GitHub comment');
    const expected = `https://api.github.com/repos/${this.connection.repository}/issues/${context.issueId}`;
    if (raw.issue_url !== expected)
      throw new Error('Comment belongs to another issue');
    return {
      id: raw.id,
      value: { body: raw.body },
      metadata: this.metadata(raw, { commentId: raw.id }),
    };
  }
  metadata(raw, identity) {
    return {
      ...identity,
      ...(raw.user?.login ? { author: raw.user.login } : {}),
      ...(raw.html_url ? { url: raw.html_url } : {}),
      ...(raw.created_at ? { createdAt: raw.created_at } : {}),
      ...(raw.updated_at ? { updatedAt: raw.updated_at } : {}),
    };
  }
  async list(entity, context = {}) {
    const result = [];
    for (let page = 1; page <= 100; page++) {
      const raw = await this.request(
        entity === 'issue' ? 'list_issues' : 'list_comments',
        {
          page,
          ...(entity === 'issue' ? {} : { number: context.issueId }),
        },
      );
      if (!Array.isArray(raw)) throw new Error('Invalid GitHub page');
      for (const r of raw) {
        if (entity === 'issue' && 'pull_request' in r) continue;
        result.push(this.row(entity, r, context));
      }
      if (raw.length < 100) return result;
    }
    throw new Error('More than 10,000 records in one scan');
  }
  async get(entity, id, context) {
    const raw = await this.request(
      entity === 'issue' ? 'get_issue' : 'get_comment',
      entity === 'issue' ? { number: id } : { id },
    );
    const row = this.row(entity, raw, context);
    if (row.id !== id) throw new Error('Provider returned another identity');
    return row;
  }
  async create(entity, value, key, metadata, context) {
    const raw = await this.request(
      entity === 'issue' ? 'create_issue' : 'create_comment',
      entity === 'issue'
        ? { title: value.title, body: value.body }
        : { number: context.issueId, body: value.body },
      `${key}:create`,
    );
    const row = this.row(entity, raw, context);
    if (entity === 'issue' && value.status !== 'Todo')
      await this.update(
        entity,
        row.id,
        value,
        `${key}:initial-state`,
        metadata,
        context,
      );
    return { ...row, value };
  }
  async update(entity, id, value, key, _metadata, context) {
    if (entity !== 'issue') {
      await this.get(entity, id, context); // validate issue membership before writing
      await this.request(
        'update_comment',
        { id, body: value.body },
        `${key}:body`,
      );
      return;
    }
    if (!['Todo', 'Doing', 'Done'].includes(value.status))
      throw new Error('Unsupported task status');
    const current = await this.get(entity, id, context);
    await this.request(
      'update_issue',
      {
        number: id,
        title: value.title,
        body: value.body,
        state: value.status === 'Done' ? 'closed' : 'open',
      },
      `${key}:fields`,
    );
    // Only this workflow label is managed. Closing preserves the label like the pilot.
    if (value.status === 'Doing' && current.value.status !== 'Doing') {
      await this.request('add_doing_label', { number: id }, `${key}:doing`);
    } else if (value.status === 'Todo') {
      // Closed issues may still carry the doing label, so inspect raw labels.
      const raw = await this.request('get_issue', { number: id });
      if (
        raw.labels.some(
          l =>
            (typeof l === 'string' ? l : l.name).toLowerCase() ===
            'atomic:doing',
        )
      ) {
        await this.request('remove_doing_label', { number: id }, `${key}:todo`);
      }
    }
  }
}

/** Signed SDK writes build on the fetched Loro state, preserving unmanaged fields. */
export class AtomicPort {
  constructor(store, config) {
    this.store = store;
    this.config = config;
    this.connection = config.connection;
    this.scope = `https://atomicdata.dev/devonian-local/${encodeURIComponent(this.connection.table)}`;
  }
  async subjects(property, value) {
    const result = await this.store.queryLocalDb({
      drive: this.connection.drive,
      property,
      value,
      limit: 10001,
    });
    if (
      !result ||
      result.count > 10000 ||
      result.subjects.length !== result.count
    )
      throw new Error('Incomplete local database query');
    return result.subjects;
  }
  async findByLocalId(parent, localId) {
    const rows = await Promise.all(
      (await this.subjects(core.properties.localId, localId)).map(id =>
        this.resource(id),
      ),
    );
    const matches = rows.filter(r => r.get(core.properties.parent) === parent);
    if (matches.length > 1)
      throw new Error('Duplicate Atomic creation identity');
    return matches[0];
  }
  async resource(subject) {
    const r = await this.store.getResource(subject);
    if (r.error) throw r.error;
    r.getLoroDoc();
    return r;
  }
  row(entity, r, context = {}) {
    const c = this.connection;
    const classes = r.get(core.properties.isA) ?? [];
    if (entity === 'issue') {
      if (
        !classes.includes(c.rowClass) ||
        r.get(core.properties.parent) !== c.table
      )
        throw new Error('Resource is not a row of this issue tracker');
    } else if (
      !classes.includes(dataBrowser.classes.message) ||
      r.get(dataBrowser.properties.about) !== context.issueId
    )
      throw new Error('Message belongs to another issue');
    let metadata = r.get(this.config.provenance);
    if (typeof metadata === 'string') metadata = JSON.parse(metadata);
    if (entity !== 'issue')
      return {
        id: r.subject,
        value: { body: r.get(core.properties.description) ?? '' },
        ...(metadata ? { metadata } : {}),
      };
    const statuses = r.get(c.status) ?? [c.tags.Todo];
    const status = Object.keys(c.tags).find(s => c.tags[s] === statuses[0]);
    if (statuses.length !== 1 || !status)
      throw new Error(
        'Choose exactly one Todo/Doing/Done status; Blocked is unmapped',
      );
    const title = r.get(core.properties.name),
      body = r.get(c.body) ?? '';
    if (typeof title !== 'string' || !title.trim() || typeof body !== 'string')
      throw new Error('Invalid Atomic issue');
    const remoteId = r.get(c.number);
    if (
      remoteId !== undefined &&
      (!Number.isSafeInteger(remoteId) || remoteId <= 0)
    )
      throw new Error('Invalid GitHub issue number');
    return {
      id: r.subject,
      remoteId,
      value: { title, body, status },
      ...(metadata ? { metadata } : {}),
    };
  }
  async list(entity, context = {}) {
    const ids = await this.subjects(
      entity === 'issue'
        ? core.properties.parent
        : dataBrowser.properties.about,
      entity === 'issue' ? this.connection.table : context.issueId,
    );
    const rows = [];
    for (const id of ids) {
      const resource = await this.resource(id);
      if (
        !(resource.get(core.properties.isA) ?? []).includes(
          entity === 'issue'
            ? this.connection.rowClass
            : dataBrowser.classes.message,
        )
      )
        continue;
      rows.push(this.row(entity, resource, context));
    }
    return rows;
  }
  async get(entity, id, context) {
    return this.row(entity, await this.resource(id), context);
  }
  values(entity, value, metadata, context) {
    const c = this.connection;
    return {
      ...(entity === 'issue'
        ? {
            [core.properties.name]: value.title,
            [c.body]: value.body,
            [c.status]: [c.tags[value.status]],
            ...(metadata?.number ? { [c.number]: metadata.number } : {}),
          }
        : {
            [core.properties.description]: value.body,
            [dataBrowser.properties.about]: context.issueId,
          }),
      ...(metadata ? { [this.config.provenance]: metadata } : {}),
    };
  }
  async create(entity, value, key, metadata, context) {
    const parent =
      entity === 'issue' ? this.connection.table : this.config.commentsFolder;
    const localId = `devonian:${await digest(key)}`;
    const existing = await this.findByLocalId(parent, localId);
    if (existing) {
      const row = await this.get(entity, existing.subject, context);
      if (!equal(row.value, value))
        throw new Error(
          'Recovered Atomic create was edited; reconcile before retry',
        );
      return row;
    }
    const r = await this.store.newResource({
      parent,
      isA: [
        entity === 'issue'
          ? this.connection.rowClass
          : dataBrowser.classes.message,
      ],
      propVals: {
        ...this.values(entity, value, metadata, context),
        [core.properties.localId]: localId,
      },
    });
    if ((await r.save()) === 'offline')
      throw new Error('AtomicServer disconnected');
    return this.get(entity, r.subject, context);
  }
  async update(entity, id, value, _key, metadata, context) {
    const r = await this.resource(id);
    this.row(entity, r, context);
    for (const [p, v] of Object.entries(
      this.values(entity, value, metadata, context),
    ))
      await r.set(p, v);
    if ((await r.save()) === 'offline')
      throw new Error('AtomicServer disconnected');
  }
}
