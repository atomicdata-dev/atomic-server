// browser/lib/src/import-resolution.ts
var IMPORT_RESOLUTION = "https://atomicdata.dev/properties/importResolution";
var IMPORT_REFERENCE_REVIEW = "https://atomicdata.dev/properties/importReferenceReview";
var base = "https://atomicdata.dev/properties/";
var ignored = /* @__PURE__ */ new Set([
  "@id",
  ...[
    "subject",
    "loroUpdate",
    "lastCommit",
    "createdAt",
    "updatedAt",
    "createdBy",
    "modifiedAt",
    "modifiedBy",
    "genesis",
    "importResolution"
  ].map((p) => base + p)
]);
function importReviewSnapshot(row) {
  return Object.fromEntries(
    Object.entries(row).filter(([key]) => !ignored.has(key))
  );
}
function equalImportValue(a, b) {
  if (a === b) return true;
  if (!a || !b || typeof a !== "object" || typeof b !== "object") return false;
  if (Array.isArray(a) || Array.isArray(b))
    return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((v, i) => equalImportValue(v, b[i]));
  const left = Object.entries(a), right = Object.keys(b);
  return left.length === right.length && left.every(
    ([key, value]) => Object.hasOwn(b, key) && equalImportValue(value, b[key])
  );
}
var pure = (s) => s.startsWith("did:") ? s.split("?")[0] : s;
function marker(row) {
  const v = row[IMPORT_RESOLUTION];
  return v?.version === 1 && typeof v.id === "string" && typeof v.canonical === "string" && v.members && typeof v.members === "object" && Array.isArray(v.supersedes) ? v : void 0;
}
function resolvedImportSubject(rows) {
  const entries = Object.entries(rows);
  if (entries.length === 1 && !entries[0][1][IMPORT_RESOLUTION])
    return entries[0][0];
  const winners = entries.filter(([subject, row]) => {
    const resolution = marker(row);
    if (!resolution || resolution.canonical !== pure(subject) || Object.keys(resolution.members).length !== entries.length)
      return false;
    return entries.every(([other, value]) => {
      const reviewed = resolution.members[pure(other)];
      if (!reviewed) return false;
      if (other === subject) return true;
      const otherMarker = marker(value);
      return (!otherMarker || resolution.supersedes.includes(otherMarker.id)) && equalImportValue(reviewed, importReviewSnapshot(value));
    });
  });
  return winners.length === 1 ? winners[0][0] : void 0;
}

// browser/lib/src/import-records.ts
var IMPORT_LOCAL_ID = "https://atomicdata.dev/properties/localId";
var IMPORT_BASELINE = "https://atomicdata.dev/properties/importBaseline";
var PARENT = "https://atomicdata.dev/properties/parent";
var IS_A = "https://atomicdata.dev/properties/isA";
function canonical(value) {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && typeof value === "object")
    return "{" + Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => JSON.stringify(k) + ":" + canonical(v)).join(",") + "}";
  return JSON.stringify(value) ?? "undefined";
}
var same = (a, b) => canonical(a) === canonical(b);
var pure2 = (subject) => typeof subject === "string" && subject.startsWith("did:") ? subject.split("?")[0] : subject;
function importRecords(host, records) {
  const intents = [], problems = [];
  const bindings = /* @__PURE__ */ new Map();
  const snapshots = /* @__PURE__ */ new Map();
  const pending = new Map(records.map((record) => [record.localId, record]));
  if (pending.size !== records.length)
    throw new Error("Duplicate localId in import batch");
  const identities = /* @__PURE__ */ new Set();
  let unchanged = 0, created = 0, updated = 0;
  const read = (subject) => {
    if (!snapshots.has(subject)) snapshots.set(subject, host.read(subject));
    return snapshots.get(subject);
  };
  const resolve = (value) => {
    if (typeof value === "string" && value.startsWith("local:")) {
      const id = value.slice(6);
      if (!bindings.has(id))
        throw new Error(`Unknown import reference ${value}`);
      return bindings.get(id);
    }
    if (Array.isArray(value)) return value.map(resolve);
    if (value && typeof value === "object")
      return Object.fromEntries(
        Object.entries(value).map(([k, v]) => [k, resolve(v)])
      );
    return value;
  };
  const destinations = /* @__PURE__ */ new Map();
  while (pending.size) {
    let progress = false;
    for (const [id, record] of pending) {
      if (!record.sourceId || !id)
        throw new Error("Import records need sourceId and localId");
      if (record.parent.startsWith("local:") && !bindings.has(record.parent.slice(6)))
        continue;
      const parent = resolve(record.parent);
      destinations.set(id, parent);
      const key = canonical([pure2(parent), record.sourceId]);
      if (identities.has(key))
        throw new Error(
          "Duplicate destination/source identity in import batch"
        );
      identities.add(key);
      let matches = [];
      if (!parent.startsWith("local:")) {
        const match = (property, value) => host.query(property, value).filter((subject2) => {
          const row = read(subject2);
          return pure2(row[PARENT]) === pure2(parent) && same(row[property], value);
        });
        matches = match(IMPORT_LOCAL_ID, record.sourceId);
        if (!matches.length && record.legacy)
          matches = match(record.legacy.property, record.legacy.value);
      }
      let unresolved = false;
      if (matches.length > 1 || matches[0] && read(matches[0])[IMPORT_RESOLUTION]) {
        const resolved = resolvedImportSubject(
          Object.fromEntries(matches.map((subject2) => [subject2, read(subject2)]))
        );
        if (resolved) matches = [resolved];
        else unresolved = true;
      }
      if (unresolved) {
        problems.push({
          severity: "error",
          message: "Multiple records represent the same source. Review both before importing again.",
          property: IMPORT_LOCAL_ID,
          importCollision: [...matches].sort()
        });
        return {
          intents,
          problems,
          summary: { created: 0, updated: 0, unchanged: 0 }
        };
      }
      const subject = matches[0];
      if (subject) {
        const current = read(subject);
        const classes = current[IS_A];
        if (!Array.isArray(classes) || record.isA.some((klass) => !classes.includes(klass)))
          throw new Error("Import identity belongs to a different class");
        const persisted = current[IMPORT_LOCAL_ID];
        if (persisted !== void 0 && persisted !== record.sourceId)
          throw new Error("Existing record belongs to another import identity");
      }
      bindings.set(id, subject ?? `local:${id}`);
      pending.delete(id);
      progress = true;
    }
    if (!progress) throw new Error("Import parent cycle");
  }
  for (const record of records) {
    for (const key of [
      PARENT,
      IS_A,
      IMPORT_LOCAL_ID,
      IMPORT_BASELINE,
      IMPORT_RESOLUTION,
      IMPORT_REFERENCE_REVIEW
    ]) {
      if (key in record.values)
        throw new Error(
          "Source values cannot set import identity or baseline metadata"
        );
    }
    const values = resolve(record.values);
    const subject = bindings.get(record.localId);
    if (subject.startsWith("local:")) {
      intents.push({
        op: "create",
        localId: record.localId,
        parent: destinations.get(record.localId),
        isA: record.isA,
        set: {
          ...values,
          [IMPORT_LOCAL_ID]: record.sourceId,
          [IMPORT_BASELINE]: { values, previous: {} }
        }
      });
      created++;
      continue;
    }
    const current = read(subject);
    const baseline = current[IMPORT_BASELINE];
    if (baseline && (!baseline.values || typeof baseline.values !== "object" || Array.isArray(baseline.values)))
      throw new Error("Invalid saved import baseline");
    const prior = baseline?.values;
    const next = { ...prior, ...values };
    const set = {};
    let conflict = false;
    for (const [property, incoming] of Object.entries(values)) {
      const changedAppendSource = !!prior && record.mode === "append" && !same(prior[property], incoming);
      if (same(current[property], incoming) && !changedAppendSource) continue;
      if (!prior || changedAppendSource || !same(current[property], prior[property]) && !same(incoming, prior[property])) {
        problems.push({
          severity: "error",
          subject,
          property,
          importConflict: {
            source: incoming,
            current: current[property],
            previous: prior?.[property],
            appendOnly: record.mode === "append"
          },
          message: prior ? "Source and local values conflict; resolve this record before importing." : "Existing record has no import baseline and differs from the source; review it before adoption."
        });
        conflict = true;
        continue;
      }
      if (same(incoming, prior[property])) continue;
      set[property] = incoming;
    }
    if (conflict) continue;
    if (!same(prior, next))
      set[IMPORT_BASELINE] = { values: next, previous: prior ?? {} };
    if (current[IMPORT_LOCAL_ID] === void 0)
      set[IMPORT_LOCAL_ID] = record.sourceId;
    if (Object.keys(set).length) {
      intents.push({ op: "set", subject, set });
      updated++;
    } else unchanged++;
  }
  return { intents, problems, summary: { created, updated, unchanged } };
}

// integrations/localthought/plugin.ts
var manifest = { schemaVersion: 1, operations: [], secrets: [] };
function run(ctx) {
  const c = ctx.config;
  if (!c.destinations || !c.properties || !Array.isArray(c.records))
    throw new Error("Fetch records from the connection before previewing this import");
  const identities = /* @__PURE__ */ new Set();
  const records = c.records.map((row) => {
    if (!row.id || !row.resource) throw new Error("Provider record is missing a stable identity");
    const target = c.destinations[row.resource];
    if (!target) throw new Error("No typed destination for provider collection");
    const sourceId = JSON.stringify([c.platform, row.resource, row.namespace, row.id]);
    if (identities.has(sourceId)) throw new Error("Provider returned duplicate record identity");
    identities.add(sourceId);
    const values = {
      "https://atomicdata.dev/properties/name": String(row.name)
    };
    for (const [field, value] of Object.entries(row.values)) {
      const property = c.properties[field];
      if (!property) throw new Error(`No ontology property for ${field}`);
      values[property] = value;
    }
    return { sourceId, localId: sourceId, parent: target.table, isA: [target.rowClass], values };
  });
  return importRecords(ctx, records);
}
export {
  manifest,
  run
};
