import { reconcileRecord } from '../../../browser/lib/src/plugin-reconcile.js';

const p = {
  title: 'https://atomicdata.dev/properties/name',
  body: 'https://atomicdata.dev/task/v1/body',
  status: 'https://atomicdata.dev/task/v1/status',
};
const tag = 'https://atomicdata.dev/task/v1/';
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const copy = value => structuredClone(value);

/** Single-writer, checkpointed reconciliation. Ports own transport and durable writes. */
export class Bridge {
  constructor({ devonian, local, remote, base, snapshot, save }) {
    this.api = devonian;
    this.local = local;
    this.remote = remote;
    this.save = save;
    const { AtomicSchema, AtomicStore, AtomicIdentityMap, Datatype } = devonian;
    this.store = new AtomicStore(
      new AtomicSchema()
        .property(p.title, Datatype.STRING)
        .property(p.body, Datatype.MARKDOWN)
        .property(p.status, Datatype.RESOURCEARRAY),
    );
    this.identities = new AtomicIdentityMap(this.store, base);
    this.binding = { base, local: local.scope, remote: remote.scope };
    if (snapshot && !equal(snapshot.binding, this.binding))
      throw new Error('State belongs to another connection');
    if (snapshot?.graph) this.store.loadJSONAD(snapshot.graph);
    this.records = copy(snapshot?.records ?? {});
  }

  scope(side, entity) {
    return { scope: this[side].scope, entity };
  }
  id(side, entity, subject) {
    return this.identities.externalId(this.scope(side, entity), subject);
  }
  context(side, entity) {
    if (entity === 'issue') return {};
    const parent = entity.slice('comment:'.length);
    const issueId = this.id(side, 'issue', parent);
    if (issueId === undefined)
      throw new Error('Issue must be mapped before comments');
    return { issueId };
  }
  async checkpoint() {
    await this.save({
      version: 1,
      binding: this.binding,
      graph: this.store.toJSONAD(),
      records: copy(this.records),
    });
  }
  properties(value) {
    return {
      [p.body]: value.body,
      ...(value.title === undefined
        ? {}
        : {
            [p.title]: value.title,
            [p.status]: [`${tag}${value.status.toLowerCase()}`],
          }),
    };
  }
  value(resource, entity) {
    if (entity !== 'issue') return { body: resource[p.body] };
    const status = {
      [`${tag}todo`]: 'Todo',
      [`${tag}doing`]: 'Doing',
      [`${tag}done`]: 'Done',
    }[resource[p.status]?.[0]];
    if (!status || resource[p.status].length !== 1)
      throw new Error('Unsupported task status');
    return { title: resource[p.title], body: resource[p.body], status };
  }
  lens(side, entity, operation, metadata) {
    const port = this[side],
      context = this.context(side, entity);
    return new this.api.AtomicLens({
      store: this.store,
      identities: this.identities,
      ...this.scope(side, entity),
      connector: {
        id: row => row.id,
        get: id => port.get(entity, id, context),
        create: (row, key) =>
          port.create(entity, row.value, key, metadata, context),
        update: (id, row) =>
          port.update(
            entity,
            id,
            row.value,
            `${operation}:${side}`,
            metadata,
            context,
          ),
        delete: async () => {
          throw new Error('Deletion is outside issue sync');
        },
      },
      read: row => ({ set: this.properties(row.value) }),
      write: (resource, previous) => ({
        ...previous,
        value: this.value(resource, entity),
      }),
    });
  }

  async sync() {
    // Resume saved operations BEFORE discovering their newly-created counterparts.
    for (const [subject, record] of Object.entries(this.records)) {
      if (record.pending) await this.finish(subject, record);
    }
    await this.syncEntity('issue');
    for (const [subject, record] of Object.entries(this.records)) {
      if (record.entity === 'issue')
        await this.syncEntity(`comment:${subject}`);
    }
  }

  async syncEntity(entity) {
    const lists = {};
    for (const side of ['remote', 'local']) {
      const rows = await this[side].list(entity, this.context(side, entity));
      lists[side] = new Map();
      for (const row of rows) {
        if (lists[side].has(row.id))
          throw new Error('Duplicate external identity');
        lists[side].set(row.id, row);
      }
    }
    // An existing pilot's explicit issue-number column is an identity, never a title match.
    for (const row of lists.local.values()) {
      if (row.remoteId === undefined) continue;
      const scope = this.scope('remote', entity);
      const subject = this.identities.subjectFor(scope, row.remoteId);
      this.identities.bind(scope, row.remoteId, subject);
      this.identities.bind(this.scope('local', entity), row.id, subject);
      this.records[subject] ??= { entity };
    }
    for (const side of ['remote', 'local']) {
      for (const row of lists[side].values()) {
        let subject = this.identities.lookup(this.scope(side, entity), row.id);
        if (!subject) subject = await this.lens(side, entity).ingest(row);
        this.records[subject] ??= { entity };
      }
    }
    await this.checkpoint();
    for (const [subject, record] of Object.entries(this.records)) {
      if (record.entity !== entity) continue;
      const rows = {};
      for (const side of ['local', 'remote']) {
        const id = this.id(side, entity, subject);
        rows[side] = id === undefined ? undefined : lists[side].get(id);
        if (id !== undefined && !rows[side])
          throw new Error(`Missing ${side} record: ${subject}`);
      }
      const decision = reconcileRecord(
        record.baseline,
        rows.local?.value,
        rows.remote?.value,
      );
      if (decision.conflicts.length)
        throw new Error(
          `Conflict on ${subject}: ${decision.conflicts.map(c => c.property).join(', ')}`,
        );
      const desired = {
        ...(rows.remote?.value ?? rows.local?.value),
        ...decision.remote,
      };
      const metadata = rows.remote?.metadata;
      if (
        rows.local &&
        rows.remote &&
        equal(rows.local.value, rows.remote.value) &&
        equal(rows.local.metadata, metadata)
      ) {
        record.baseline = copy(desired);
        await this.checkpoint();
        continue;
      }
      record.pending = {
        operation: crypto.randomUUID(),
        local: rows.local?.value,
        remote: rows.remote?.value,
        desired,
        metadata,
      };
      this.store.patch(subject, { set: this.properties(desired) });
      await this.checkpoint();
      await this.finish(subject, record);
    }
  }

  async finish(subject, record) {
    const { pending, entity } = record;
    // A retry accepts only the original observation or this operation's exact result.
    for (const side of ['local', 'remote']) {
      const id = this.id(side, entity, subject);
      if (id === undefined) continue;
      const row = await this[side].get(entity, id, this.context(side, entity));
      if (
        !equal(row.value, pending[side]) &&
        !equal(row.value, pending.desired)
      )
        throw new Error(`Conflict during saved operation on ${subject}`);
    }
    for (const side of ['remote', 'local']) {
      const id = this.id(side, entity, subject);
      const row =
        id === undefined
          ? undefined
          : await this[side].get(entity, id, this.context(side, entity));
      if (
        !row ||
        !equal(row.value, pending.desired) ||
        (side === 'local' && !equal(row.metadata, pending.metadata))
      ) {
        await this.lens(
          side,
          entity,
          pending.operation,
          pending.metadata,
        ).publish(subject);
        await this.checkpoint();
      }
    }
    for (const side of ['local', 'remote']) {
      const row = await this[side].get(
        entity,
        this.id(side, entity, subject),
        this.context(side, entity),
      );
      if (!equal(row.value, pending.desired))
        throw new Error(`Concurrent edit after write on ${subject}`);
    }
    record.baseline = copy(pending.desired);
    delete record.pending;
    await this.checkpoint();
  }
}
