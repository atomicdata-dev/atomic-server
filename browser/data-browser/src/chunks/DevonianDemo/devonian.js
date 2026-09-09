// Devonian native resource API, e11104f78ebd151a361171ca0b21489b25e1e2c8. Apache-2.0; see DEVONIAN-LICENSE.

// ../../localthought/devonian/src/atomic/Resource.ts
import { Datatype, validateDatatype } from "@tomic/lib";
var IS_A = "https://atomicdata.dev/properties/isA";
function assertSubject(value) {
  if (typeof value !== "string" || /\s/.test(value))
    throw new Error("Expected an absolute URL without whitespace");
  const url = new URL(value);
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error(`Expected an HTTP(S) URL: ${value}`);
  }
}
var AtomicSchema = class {
  properties = /* @__PURE__ */ new Map([
    [IS_A, Datatype.RESOURCEARRAY]
  ]);
  property(subject, datatype) {
    assertSubject(subject);
    if (!Object.values(Datatype).includes(datatype) || datatype === Datatype.UNKNOWN) {
      throw new Error(`Unsupported datatype: ${datatype}`);
    }
    const existing = this.properties.get(subject);
    if (existing && existing !== datatype)
      throw new Error(`Conflicting property: ${subject}`);
    this.properties.set(subject, datatype);
    return this;
  }
  validate(resource) {
    assertSubject(resource["@id"]);
    this.validateProperties(resource, true);
  }
  validateProperties(resource, named) {
    if (Object.getPrototypeOf(resource) !== Object.prototype)
      throw new Error("Expected a plain JSON object");
    for (const [property, value] of Object.entries(resource)) {
      if (property === "@id" && named) continue;
      assertSubject(property);
      const datatype = this.properties.get(property);
      if (!datatype) throw new Error(`Unknown property: ${property}`);
      if (typeof value === "number" && !Number.isFinite(value))
        throw new Error("Expected a finite number");
      if (value === void 0 || value === null)
        throw new Error(`Missing value for ${property}`);
      if (datatype === Datatype.ATOMIC_URL) {
        this.validateLink(value);
      } else if (datatype === Datatype.RESOURCEARRAY) {
        if (!Array.isArray(value))
          throw new Error(`Expected a resource array: ${property}`);
        for (const link of value) this.validateLink(link);
      } else {
        if ([Datatype.FLOAT, Datatype.INTEGER, Datatype.TIMESTAMP].includes(
          datatype
        ) && typeof value !== "number")
          throw new Error("Expected a number");
        if (datatype === Datatype.BOOLEAN && typeof value !== "boolean")
          throw new Error("Expected a boolean");
        validateDatatype(value, datatype);
      }
    }
  }
  validateLink(value) {
    if (typeof value === "string") assertSubject(value);
    else if (value && typeof value === "object" && !Array.isArray(value))
      this.validateProperties(value, false);
    else throw new Error("Expected a resource URL or nested resource");
  }
};

// ../../localthought/devonian/src/atomic/Store.ts
var AtomicStore = class _AtomicStore {
  constructor(schema) {
    this.schema = schema;
  }
  schema;
  resources = /* @__PURE__ */ new Map();
  get(subject) {
    const resource = this.resources.get(subject);
    return resource && structuredClone(resource);
  }
  put(resource) {
    this.schema.validate(resource);
    this.resources.set(resource["@id"], structuredClone(resource));
  }
  /** Preserve omitted properties; removals must be listed in unset. */
  patch(subject, patch) {
    assertSubject(subject);
    if (Object.hasOwn(patch.set ?? {}, "@id") || patch.unset?.includes("@id")) {
      throw new Error("A patch cannot change resource identity");
    }
    const resource = {
      ...this.get(subject) ?? { "@id": subject },
      ...patch.set
    };
    for (const property of patch.unset ?? []) {
      assertSubject(property);
      delete resource[property];
    }
    this.put(resource);
    return structuredClone(resource);
  }
  /** Synchronous local transaction. Async work must finish before entering this callback. */
  transaction(operation) {
    const previous = this.resources;
    this.resources = new Map(previous);
    try {
      operation();
    } catch (error) {
      this.resources = previous;
      throw error;
    }
  }
  /** Apply a resource projection as one local transaction. */
  apply(changes) {
    const staged = new _AtomicStore(this.schema);
    staged.resources = new Map(this.resources);
    for (const change of changes) staged.patch(change.subject, change.patch);
    this.resources = staged.resources;
  }
  delete(subject) {
    this.resources.delete(subject);
  }
  /** Optional class filtering; callers can apply additional predicates to the returned copies. */
  all(classSubject) {
    return [...this.resources.values()].filter((resource) => {
      const classes = resource["https://atomicdata.dev/properties/isA"];
      return !classSubject || Array.isArray(classes) && classes.includes(classSubject);
    }).map((resource) => structuredClone(resource));
  }
  toJSONAD() {
    return JSON.stringify(this.all());
  }
  /** Validate the complete snapshot before replacing state. Import does not emit writes. */
  loadJSONAD(json) {
    const parsed = JSON.parse(json);
    const resources = Array.isArray(parsed) ? parsed : [parsed];
    const next = /* @__PURE__ */ new Map();
    for (const item of resources) {
      if (!item || typeof item !== "object" || Array.isArray(item) || typeof item["@id"] !== "string") {
        throw new Error("Expected a named JSON-AD resource");
      }
      const resource = item;
      this.schema.validate(resource);
      if (next.has(resource["@id"]))
        throw new Error(`Duplicate subject: ${resource["@id"]}`);
      next.set(resource["@id"], structuredClone(resource));
    }
    this.resources = next;
  }
};

// ../../localthought/devonian/src/atomic/IdentityMap.ts
var VOCAB = "https://raw.githubusercontent.com/localthought/devonian/main/vocab/";
var identity = {
  class: `${VOCAB}Identity.json`,
  scope: `${VOCAB}scope.json`,
  entity: `${VOCAB}entity.json`,
  localId: `${VOCAB}localId.json`,
  idType: `${VOCAB}idType.json`,
  resource: `${VOCAB}resource.json`
};
var AtomicIdentityMap = class {
  constructor(store, baseURL) {
    this.store = store;
    assertSubject(baseURL);
    const url = new URL(baseURL);
    if (url.search || url.hash)
      throw new Error("Identity base URL cannot contain a query or fragment");
    this.base = baseURL.replace(/\/$/, "");
    store.schema.property(identity.scope, Datatype.ATOMIC_URL).property(identity.entity, Datatype.STRING).property(identity.localId, Datatype.STRING).property(identity.idType, Datatype.STRING).property(identity.resource, Datatype.ATOMIC_URL);
  }
  store;
  base;
  key(scope, id) {
    assertSubject(scope.scope);
    if (!scope.entity || typeof id !== "string" && typeof id !== "number" || typeof id === "number" && !Number.isSafeInteger(id) || id === "") {
      throw new Error(
        "Expected an entity and a nonempty string or safe integer external ID"
      );
    }
    return encodeURIComponent(
      JSON.stringify([scope.scope, scope.entity, typeof id, id])
    );
  }
  subjectFor(scope, id) {
    return this.lookup(scope, id) ?? `${this.base}/resources/${this.key(scope, id)}`;
  }
  lookup(scope, id) {
    this.key(scope, id);
    return this.find(scope).find(
      (resource) => resource[identity.localId] === String(id) && resource[identity.idType] === typeof id
    )?.[identity.resource];
  }
  externalId(scope, subject) {
    const resource = this.find(scope).find(
      (resource2) => resource2[identity.resource] === subject
    );
    if (!resource) return void 0;
    return resource[identity.idType] === "number" ? Number(resource[identity.localId]) : resource[identity.localId];
  }
  bind(scope, id, subject) {
    const key = this.key(scope, id);
    assertSubject(subject);
    const existing = this.lookup(scope, id);
    const reverse = this.externalId(scope, subject);
    if (existing !== void 0 && existing !== subject || reverse !== void 0 && reverse !== id) {
      throw new Error("Conflicting identity mapping");
    }
    if (existing === subject && reverse === id) return;
    this.store.put({
      "@id": `${this.base}/identities/${key}`,
      [IS_A]: [identity.class],
      [identity.scope]: scope.scope,
      [identity.entity]: scope.entity,
      [identity.localId]: String(id),
      [identity.idType]: typeof id,
      [identity.resource]: subject
    });
  }
  find(scope) {
    const resources = this.store.all(identity.class).filter(
      (resource) => resource[identity.scope] === scope.scope && resource[identity.entity] === scope.entity
    );
    const ids = /* @__PURE__ */ new Set();
    const subjects = /* @__PURE__ */ new Set();
    for (const resource of resources) {
      const id = resource[identity.localId];
      const type = resource[identity.idType];
      const subject = resource[identity.resource];
      if (typeof id !== "string" || !id || !["string", "number"].includes(String(type)) || typeof subject !== "string" || type === "number" && (!Number.isSafeInteger(Number(id)) || String(Number(id)) !== id)) {
        throw new Error("Invalid identity mapping");
      }
      const key = JSON.stringify([type, id]);
      if (ids.has(key) || subjects.has(subject))
        throw new Error("Conflicting identity mappings in snapshot");
      ids.add(key);
      subjects.add(subject);
    }
    return resources;
  }
};

// ../../localthought/devonian/src/atomic/Lens.ts
var AtomicLens = class {
  constructor(options) {
    this.options = options;
    assertSubject(options.scope);
    if (!options.entity) throw new Error("A lens requires an entity type");
    if (options.identities.store !== options.store) {
      throw new Error("Lens and identity map must use the same store");
    }
  }
  options;
  pending = Promise.resolve();
  /** Handle a webhook or fetched record. Never writes back to the connector. */
  ingest(record) {
    return this.enqueue(async () => {
      const { connector, identities, store, read } = this.options;
      const id = connector.id(record);
      const subject = identities.subjectFor(this.options, id);
      const patch = await read(record, subject);
      store.transaction(() => {
        store.apply([...patch.related ?? [], { subject, patch }]);
        for (const mapping of patch.identities ?? [])
          identities.bind(mapping.scope, mapping.id, mapping.subject);
        identities.bind(this.options, id, subject);
      });
      return subject;
    });
  }
  /** Publish the latest native state; failures reject and may be retried. */
  publish(subject) {
    return this.enqueue(async () => {
      const { connector, identities, store, write } = this.options;
      const resource = store.get(subject);
      if (!resource) throw new Error(`Unknown resource: ${subject}`);
      const id = identities.externalId(this.options, subject);
      if (id !== void 0) {
        const previous = await connector.get(id);
        await connector.update(id, await write(resource, previous));
        return id;
      }
      const key = JSON.stringify([
        this.options.scope,
        this.options.entity,
        subject
      ]);
      const created = await connector.create(
        await write(resource, void 0),
        key
      );
      const createdId = connector.id(created);
      identities.bind(this.options, createdId, subject);
      return createdId;
    });
  }
  /** Delete native state after an external deletion. Retain identity for replay/recreation. */
  ingestDelete(id) {
    return this.enqueue(async () => {
      const subject = this.options.identities.lookup(this.options, id);
      if (subject) this.options.store.delete(subject);
    });
  }
  /** Delete externally first, so a failed request leaves native state available for retry. */
  delete(subject) {
    return this.enqueue(async () => {
      const { connector, identities, store } = this.options;
      const id = identities.externalId(this.options, subject);
      if (id !== void 0) await connector.delete(id);
      store.delete(subject);
    });
  }
  enqueue(operation) {
    const result = this.pending.then(operation);
    this.pending = result.catch(() => void 0);
    return result;
  }
};
export {
  AtomicIdentityMap,
  AtomicLens,
  AtomicSchema,
  AtomicStore,
  Datatype,
  IS_A,
  assertSubject,
  identity
};
