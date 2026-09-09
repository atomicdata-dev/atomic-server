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
      const id2 = value.slice(6);
      if (!bindings.has(id2))
        throw new Error(`Unknown import reference ${value}`);
      return bindings.get(id2);
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
    for (const [id2, record] of pending) {
      if (!record.sourceId || !id2)
        throw new Error("Import records need sourceId and localId");
      if (record.parent.startsWith("local:") && !bindings.has(record.parent.slice(6)))
        continue;
      const parent = resolve(record.parent);
      destinations.set(id2, parent);
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
      bindings.set(id2, subject ?? `local:${id2}`);
      pending.delete(id2);
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

// integrations/clockify/model.ts
var origin = "https://api.clockify.me";
var api = `${origin}/api/v1`;
function id(value) {
  if (!/^[a-f\d]{24}$/i.test(value))
    throw new Error("Invalid Clockify identifier");
  return value;
}
function request(operation, url, run2 = operation) {
  return {
    operation,
    method: "GET",
    url,
    id: run2,
    headers: { "X-Api-Key": "secret:clockify" }
  };
}
function parse(receipt) {
  if (receipt.status !== 200)
    throw new Error(
      `Clockify returned ${receipt.status}. Check access and API limits, then retry.`
    );
  return JSON.parse(receipt.body);
}

// integrations/clockify/plugin.ts
var P = {
  name: "https://atomicdata.dev/properties/name",
  parent: "https://atomicdata.dev/properties/parent"
};
function run(ctx) {
  if (ctx.phase === "discover") return discover(ctx);
  return importEntries(ctx, settings, ctx.trigger?.at);
}
function discover(ctx) {
  const account = parse(ctx.http(request("user", `${api}/user`)));
  const workspaces = parse(
    ctx.http(request("workspaces", `${api}/workspaces`))
  );
  if (!account || typeof account.name !== "string")
    throw new Error("Clockify returned invalid account details");
  id(account.id);
  if (!Array.isArray(workspaces) || workspaces.length > 1e3)
    throw new Error("Clockify returned invalid workspace details");
  const seen = /* @__PURE__ */ new Set();
  const spaces = workspaces.map((space) => {
    if (!space || typeof space.name !== "string")
      throw new Error("Clockify returned invalid workspace details");
    id(space.id);
    if (seen.has(space.id))
      throw new Error("Clockify returned duplicate workspaces");
    seen.add(space.id);
    return { id: space.id, name: space.name };
  });
  return {
    intents: [],
    problems: [],
    discovery: {
      user: { id: account.id, name: account.name },
      workspaces: spaces
    }
  };
}
function importEntries(ctx, c, at) {
  id(c.workspace);
  id(c.user);
  let from, until;
  if (c.lookbackDays !== void 0) {
    if (!Number.isInteger(c.lookbackDays) || c.lookbackDays < 1 || c.lookbackDays > 31 || typeof at !== "number" || !Number.isFinite(at))
      throw new Error(
        "A rolling import needs 1\u201331 days and a valid host trigger time"
      );
    until = at;
    from = until - c.lookbackDays * 864e5;
  } else {
    from = Date.parse(c.start ?? "");
    until = Date.parse(c.end ?? "");
  }
  if (!Number.isFinite(from) || !Number.isFinite(until) || until <= from || until - from > 31 * 864e5 || !Number.isFinite(new Date(from).getTime()) || !Number.isFinite(new Date(until).getTime()))
    throw new Error("Choose a date range of at most 31 days");
  const startDate = new Date(from).toISOString(), endDate = new Date(until).toISOString();
  const root = `${api}/workspaces/${c.workspace}`;
  const problems = [];
  const list = (operation, url) => {
    const all = [];
    const seen = /* @__PURE__ */ new Set();
    for (let page = 1; page <= 20; page++) {
      const rows = parse(
        ctx.http(
          request(
            operation,
            `${url}${url.includes("?") ? "&" : "?"}page=${page}&page-size=50`,
            `${operation}-${page}`
          )
        )
      );
      if (!Array.isArray(rows))
        throw new Error("Clockify returned an invalid page");
      for (const row of rows) {
        if (!row || typeof row !== "object" || typeof row.id !== "string")
          throw new Error("Clockify returned an invalid record");
        id(row.id);
        if (seen.has(row.id))
          throw new Error(
            "Clockify pagination repeated a record; narrow the range and retry"
          );
        seen.add(row.id);
        all.push(row);
      }
      if (rows.length < 50) return all;
    }
    throw new Error(
      "Import exceeded 1,000 records. Narrow the date range. No partial import was proposed."
    );
  };
  const matches = (identity) => {
    const subjects = ctx.query(c.properties.identity, identity);
    if (subjects.length > 1)
      throw new Error(
        "Duplicate imported identities need review before importing again"
      );
    return subjects[0];
  };
  const projects = list("projects", `${root}/projects`);
  const entries = list(
    "entries",
    `${root}/user/${c.user}/time-entries?start=${encodeURIComponent(startDate)}&end=${encodeURIComponent(endDate)}&in-progress=false`
  );
  const container = c.container ?? c.table;
  let skipped = 0;
  const records = [];
  const support = /* @__PURE__ */ new Map();
  const moves = [];
  const supportLink = (identity, klass, name, localId) => {
    if (support.has(identity)) return support.get(identity);
    let parent = container;
    const subject = matches(identity);
    if (subject) {
      const current = ctx.read(subject);
      const classes = current["https://atomicdata.dev/properties/isA"];
      if (!Array.isArray(classes) || !classes.includes(klass) || current[c.properties.identity] !== identity)
        throw new Error(
          "Imported supporting record has an unexpected identity or class"
        );
      if (typeof current[P.parent] === "string")
        parent = current[P.parent];
      if (parent === c.drive && container !== c.drive)
        moves.push({ op: "set", subject, set: { [P.parent]: container } });
    }
    records.push({
      localId,
      sourceId: identity,
      parent,
      isA: [klass],
      values: { [P.name]: name, [c.properties.identity]: identity },
      legacy: { property: c.properties.identity, value: identity }
    });
    const link = `local:${localId}`;
    support.set(identity, link);
    return link;
  };
  for (const entry of entries) {
    if (entry.userId !== c.user || entry.workspaceId && entry.workspaceId !== c.workspace)
      throw new Error(
        "Clockify returned entries for another user or workspace"
      );
    if (!entry.timeInterval?.end) {
      skipped++;
      continue;
    }
    const start = Date.parse(entry.timeInterval.start), end = Date.parse(entry.timeInterval.end);
    if (!Number.isFinite(start) || !Number.isFinite(end) || end < start)
      throw new Error("Clockify returned an invalid completed interval");
    if (start < from || start >= until) continue;
    if (entry.type && entry.type !== "REGULAR") {
      skipped++;
      continue;
    }
    if (typeof entry.description !== "string" || typeof entry.billable !== "boolean")
      throw new Error("Clockify returned invalid entry fields");
    const identity = `clockify:${c.workspace}:entry:${entry.id}`;
    let project;
    if (entry.projectId) {
      id(entry.projectId);
      const remote = projects.find((p) => p.id === entry.projectId);
      if (!remote || typeof remote.name !== "string")
        throw new Error(
          "An entry references an inaccessible project; no partial import was proposed"
        );
      project = supportLink(
        `clockify:${c.workspace}:project:${entry.projectId}`,
        c.projectClass,
        remote.name,
        `project-${entry.projectId}`
      );
    }
    const person = supportLink(
      `clockify:${c.workspace}:person:${c.user}`,
      c.personClass,
      c.userName,
      "person"
    );
    records.push({
      sourceId: identity,
      legacy: { property: c.properties.identity, value: identity },
      localId: `entry-${entry.id}`,
      parent: c.table,
      isA: [c.rowClass],
      values: {
        [P.name]: entry.description || "Time entry",
        [c.properties.start]: start,
        [c.properties.end]: end,
        [c.properties.billable]: entry.billable,
        [c.properties.identity]: identity,
        [c.properties.person]: person,
        ...project ? { [c.properties.project]: project } : {}
      }
    });
  }
  const result = importRecords(ctx, records);
  problems.push(...result.problems);
  if (moves.length)
    problems.push({
      severity: "warning",
      message: `${moves.length} previously imported root records will move inside this app. Their identities and links stay the same.`
    });
  problems.push({
    severity: "warning",
    message: `${result.summary.unchanged} unchanged records; ${skipped} running or break entries skipped. Source updates preserve local edits and conflicts need review.`
  });
  problems.push({
    severity: "warning",
    message: "Import only: tags, task links, rates and custom fields are not mapped. No records are deleted."
  });
  return { intents: [...result.intents, ...moves], problems };
}
export {
  discover,
  importEntries,
  run
};
