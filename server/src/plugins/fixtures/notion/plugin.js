var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJS = (cb, mod) => function __require() {
  try {
    return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
  } catch (e) {
    throw mod = 0, e;
  }
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// browser/node_modules/.pnpm/fast-json-stable-stringify@2.1.0/node_modules/fast-json-stable-stringify/index.js
var require_fast_json_stable_stringify = __commonJS({
  "browser/node_modules/.pnpm/fast-json-stable-stringify@2.1.0/node_modules/fast-json-stable-stringify/index.js"(exports, module) {
    "use strict";
    module.exports = function(data, opts) {
      if (!opts) opts = {};
      if (typeof opts === "function") opts = { cmp: opts };
      var cycles = typeof opts.cycles === "boolean" ? opts.cycles : false;
      var cmp = opts.cmp && /* @__PURE__ */ (function(f) {
        return function(node) {
          return function(a, b) {
            var aobj = { key: a, value: node[a] };
            var bobj = { key: b, value: node[b] };
            return f(aobj, bobj);
          };
        };
      })(opts.cmp);
      var seen = [];
      return (function stringify2(node) {
        if (node && node.toJSON && typeof node.toJSON === "function") {
          node = node.toJSON();
        }
        if (node === void 0) return;
        if (typeof node == "number") return isFinite(node) ? "" + node : "null";
        if (typeof node !== "object") return JSON.stringify(node);
        var i, out;
        if (Array.isArray(node)) {
          out = "[";
          for (i = 0; i < node.length; i++) {
            if (i) out += ",";
            out += stringify2(node[i]) || "null";
          }
          return out + "]";
        }
        if (node === null) return "null";
        if (seen.indexOf(node) !== -1) {
          if (cycles) return JSON.stringify("__cycle__");
          throw new TypeError("Converting circular structure to JSON");
        }
        var seenIndex = seen.push(node) - 1;
        var keys = Object.keys(node).sort(cmp && cmp(node));
        out = "";
        for (i = 0; i < keys.length; i++) {
          var key = keys[i];
          var value = stringify2(node[key]);
          if (!value) continue;
          if (out) out += ",";
          out += JSON.stringify(key) + ":" + value;
        }
        seen.splice(seenIndex, 1);
        return "{" + out + "}";
      })(data);
    };
  }
});

// browser/lib/src/import-records.ts
var IMPORT_LOCAL_ID = "https://atomicdata.dev/properties/localId";
var PARENT = "https://atomicdata.dev/properties/parent";
var pure = (subject) => typeof subject === "string" && subject.startsWith("did:") ? subject.split("?")[0] : subject;
function claimImportIdentity(host, parent, sourceId, subject) {
  const matches = host.query(IMPORT_LOCAL_ID, sourceId).filter((id) => pure(host.read(id)[PARENT]) === pure(parent));
  if (matches.length > 1 || matches.some((id) => pure(id) !== pure(subject)))
    throw new Error(
      "Import identity already exists; reconcile the binding before syncing"
    );
  const old = subject ? host.read(subject)[IMPORT_LOCAL_ID] : void 0;
  if (old !== void 0 && old !== sourceId)
    throw new Error("Resource belongs to another import identity");
  return { [IMPORT_LOCAL_ID]: sourceId };
}

// browser/lib/src/plugin-reconcile.ts
var import_fast_json_stable_stringify = __toESM(require_fast_json_stable_stringify(), 1);
var equal = (a, b) => (0, import_fast_json_stable_stringify.default)(a) === (0, import_fast_json_stable_stringify.default)(b);
function reconcileRecord(base2, local, remote) {
  const result = {
    local: {},
    remote: {},
    createLocal: false,
    createRemote: false,
    deleteLocal: false,
    deleteRemote: false,
    conflicts: []
  };
  if (equal(local, remote)) {
    if (local !== void 0) result.agreed = structuredClone(local);
    return result;
  }
  if (local === null || remote === null) {
    if (equal(local, base2) && remote === null) result.deleteLocal = true;
    else if (equal(remote, base2) && local === null) result.deleteRemote = true;
    else
      result.conflicts.push({
        property: "@record",
        base: base2,
        local,
        remote
      });
    return result;
  }
  if (base2 !== void 0 && (local === void 0 || remote === void 0))
    return result;
  result.createLocal = base2 === void 0 && local === void 0 && remote !== void 0;
  result.createRemote = base2 === void 0 && remote === void 0 && local !== void 0;
  const properties = /* @__PURE__ */ new Set([
    ...Object.keys(base2 ?? {}),
    ...Object.keys(local ?? {}),
    ...Object.keys(remote ?? {})
  ]);
  for (const property of properties) {
    const before = base2?.[property];
    const here = local?.[property];
    const there = remote?.[property];
    if (equal(here, there)) continue;
    if (equal(here, before)) result.local[property] = structuredClone(there);
    else if (equal(there, before))
      result.remote[property] = structuredClone(here);
    else
      result.conflicts.push({
        property,
        base: before,
        local: here,
        remote: there
      });
  }
  return result;
}

// integrations/notion/model.ts
var API_VERSION = "2026-03-11";
var base = "https://api.notion.com/v1";
var P = {
  name: "https://atomicdata.dev/properties/name",
  parent: "https://atomicdata.dev/properties/parent",
  isA: "https://atomicdata.dev/properties/isA",
  columns: "https://atomicdata.dev/properties/view-columns",
  kind: "https://atomicdata.dev/properties/view-kind",
  group: "https://atomicdata.dev/properties/view-group-by"
};
function equal2(a, b) {
  if (a === b) return true;
  if (!a || !b || typeof a !== "object" || typeof b !== "object" || Array.isArray(a) !== Array.isArray(b))
    return false;
  const x = a, y = b;
  return Object.keys(x).length === Object.keys(y).length && Object.keys(x).every((k) => Object.hasOwn(y, k) && equal2(x[k], y[k]));
}
function uuid(value) {
  if (!/^(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i.test(
    value
  ))
    throw new Error("Expected a Notion data source/page/view UUID");
  const s = value.replaceAll("-", "").toLowerCase();
  return `${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20)}`;
}
function request(operation, method, path, body, id = operation) {
  return {
    id,
    operation,
    method,
    url: base + path,
    headers: {
      Authorization: "secret:notion",
      "Notion-Version": API_VERSION,
      "Content-Type": "application/json"
    },
    ...body === void 0 ? {} : { body: JSON.stringify(body) }
  };
}
function parse(receipt) {
  if (receipt.status < 200 || receipt.status >= 300)
    throw new Error(
      `Notion returned ${receipt.status}; sync paused, no deletion inferred`
    );
  return JSON.parse(receipt.body);
}
function plainText(parts) {
  if (!Array.isArray(parts)) throw new Error("Invalid Notion text");
  let text = "";
  for (const p of parts) {
    if (p.type !== "text" || typeof p.text?.content !== "string" || p.text.link || p.annotations && Object.entries(p.annotations).some(
      ([k, v]) => k === "color" ? v !== "default" : v !== false
    ))
      throw new Error(
        "Formatted text or mentions need a lossless mapping; this field cannot sync as plain text"
      );
    text += p.text.content;
  }
  return text;
}
function validateValue(field, value) {
  const t = field.type;
  if (t === "number" ? value !== null && (typeof value !== "number" || !Number.isFinite(value)) : t === "checkbox" ? typeof value !== "boolean" : t === "multi_select" ? !Array.isArray(value) || value.some(
    (id) => typeof id !== "string" || !field.options?.[id]
  ) : t === "select" || t === "status" ? value !== null && (typeof value !== "string" || !field.options?.[value]) : value !== null && typeof value !== "string")
    throw new Error(`Invalid or unmapped ${t} value for property ${field.id}`);
  if ((t === "title" || t === "rich_text") && typeof value !== "string")
    throw new Error("Text must be a string");
}
function projectPage(page, c) {
  if (page.object !== "page" || uuid(page.parent?.data_source_id ?? "") !== uuid(c.dataSource) || page.archived || page.in_trash)
    throw new Error(
      "Page missing, moved, archived or outside the connected data source; reconcile explicitly"
    );
  const byId = new Map(
    Object.values(page.properties ?? {}).map((v) => [v.id, v])
  );
  const result = {};
  for (const f of c.fields) {
    const p = byId.get(f.id);
    if (!p || p.type !== f.type)
      throw new Error(`Mapped property ${f.id} is missing or changed type`);
    const raw = p[f.type];
    const v = f.type === "title" || f.type === "rich_text" ? plainText(raw) : f.type === "multi_select" ? raw.map((o) => o.id).sort() : f.type === "select" || f.type === "status" ? raw?.id ?? null : raw;
    validateValue(f, v);
    result[f.id] = v;
  }
  return result;
}
function projectRow(row, c, baseline) {
  if (row[P.parent] !== c.table || !row[P.isA]?.includes(c.rowClass))
    throw new Error("Atomic row moved or changed class");
  const result = {};
  for (const f of c.fields) {
    let v = row[f.property];
    if (f.type === "title" && f.property !== P.name) {
      const display = row[P.name];
      if (v === void 0) v = display;
      else if (display !== void 0 && v !== display) {
        if (baseline && v === baseline[f.id]) v = display;
        else if (!baseline || display !== baseline[f.id])
          throw new Error(
            "Title and display name changed independently; resolve the local conflict"
          );
      }
    }
    if (f.options) {
      if (!Array.isArray(v ?? []))
        throw new Error("Select values must be Atomic tag arrays");
      const ids = (v ?? []).map((tag) => {
        const id = Object.entries(f.options).find(([, p]) => p === tag)?.[0];
        if (!id) throw new Error("Unmapped Atomic select option");
        return id;
      }).sort();
      if (f.type !== "multi_select" && ids.length > 1)
        throw new Error("Select/status supports at most one option");
      v = f.type === "multi_select" ? ids : ids[0] ?? null;
    } else
      v ??= f.type === "checkbox" ? false : f.type === "title" || f.type === "rich_text" ? "" : null;
    validateValue(f, v);
    result[f.id] = v;
  }
  return result;
}
function pagePatch(desired, previous, c) {
  const properties = {};
  for (const f of c.fields) {
    const value = desired[f.id];
    validateValue(f, value);
    if (previous && equal2(previous[f.id], value)) continue;
    let encoded = value;
    if (f.type === "title" || f.type === "rich_text") {
      const text = value;
      const parts = [];
      for (let i = 0; i < text.length; ) {
        let end = Math.min(i + 2e3, text.length);
        if (end < text.length && /[\uD800-\uDBFF]/.test(text[end - 1])) end--;
        parts.push({ type: "text", text: { content: text.slice(i, end) } });
        i = end;
      }
      if (parts.length > 100)
        throw new Error("Text exceeds Notion's block-array limit");
      encoded = parts;
    } else if (f.type === "multi_select")
      encoded = value.map((id) => ({ id }));
    else if (f.type === "select" || f.type === "status")
      encoded = value === null ? null : { id: value };
    properties[f.id] = { [f.type]: encoded };
  }
  return properties;
}
function rowPatch(desired, c) {
  const set = {};
  const remove = [];
  for (const f of c.fields) {
    const v = desired[f.id];
    validateValue(f, v);
    if (f.options)
      set[f.property] = f.type === "multi_select" ? v.map((id) => f.options[id]) : v === null ? [] : [f.options[v]];
    else if (v === null) remove.push(f.property);
    else set[f.property] = v;
  }
  const title = c.fields.find((f) => f.type === "title");
  if (title) set[P.name] = desired[title.id];
  return { set, remove };
}
function projectView(view, c) {
  if (uuid(view.data_source_id ?? "") !== uuid(c.dataSource) || !["table", "board"].includes(view.type))
    throw new Error("Unsupported view type or foreign data source");
  if (view.filter || view.sorts?.length || Object.keys(view.quick_filters ?? {}).length)
    throw new Error(
      "View filters/sorts need a lossless mapping; view not imported"
    );
  const cfg = view.configuration ?? {};
  if (cfg.subtasks && cfg.subtasks.display_mode !== "disabled" || cfg.sub_group_by)
    throw new Error("View subtasks/subgroups are not mapped");
  const columns = (cfg.properties ?? c.fields.map((f) => ({ property_id: f.id, visible: true }))).filter((p) => p.visible !== false).map((p) => p.property_id);
  if (columns.some((id) => !c.fields.some((f) => f.id === id)))
    throw new Error("View contains unmapped visible properties");
  if (cfg.group_by?.type === "status" && cfg.group_by.group_by !== "option")
    throw new Error("Status groups are not individual Atomic kanban options");
  if (!columns.length)
    throw new Error("A connected view needs visible columns");
  const group = cfg.group_by?.property_id ?? null;
  if (group && !c.fields.find((f) => f.id === group)?.options)
    throw new Error("View grouping must use a mapped select/status property");
  if (view.type === "board" && !group)
    throw new Error("Board requires an explicit mapped grouping property");
  if (view.type === "table" && group)
    throw new Error("Grouped table views are not mapped yet");
  return { name: view.name, columns, group, kind: view.type };
}
function projectLocalView(row, c, binding) {
  if (row["https://atomicdata.dev/properties/view-filters"]?.length || row["https://atomicdata.dev/properties/view-sort-by"])
    throw new Error("Connected view filters/sorts are not mapped yet");
  const kind = row[P.kind] === "kanban" ? "board" : row[P.kind];
  if (kind !== binding.kind)
    throw new Error("Changing a connected view type is not supported");
  const find = (subject) => {
    const f = c.fields.find((f2) => f2.property === subject);
    if (!f) throw new Error("View uses an unmapped Atomic property");
    return f.id;
  };
  const columns = (row[P.columns] ?? []).map(find);
  if (!columns.length)
    throw new Error("Connected view requires explicit visible columns");
  return {
    name: row[P.name],
    columns,
    group: row[P.group] ? find(row[P.group]) : null,
    kind
  };
}
function viewPatch(desired, current, c) {
  const before = projectView(current, c);
  const patch = {};
  if (desired.name !== before.name) patch.name = desired.name;
  if (!equal2(desired.columns, before.columns) || desired.group !== before.group) {
    const cfg = { ...current.configuration };
    const ids = desired.columns;
    const existing = cfg.properties ?? [];
    cfg.properties = [
      ...ids.map((id) => ({
        ...existing.find((p) => p.property_id === id),
        property_id: id,
        visible: true
      })),
      ...existing.filter((p) => !ids.includes(p.property_id)).map((p) => ({ ...p, visible: false }))
    ];
    if (desired.group !== before.group) {
      const f = c.fields.find((f2) => f2.id === desired.group);
      if (!f?.options || desired.kind !== "board")
        throw new Error("Unsupported view grouping change");
      cfg.group_by = {
        type: f.type,
        property_id: f.id,
        sort: { type: "manual" },
        ...f.type === "status" ? { group_by: "option" } : {}
      };
    }
    patch.configuration = cfg;
  }
  return patch;
}

// integrations/notion/plugin.ts
globalThis.structuredClone ??= ((v) => v === void 0 ? void 0 : JSON.parse(JSON.stringify(v)));
function run(input) {
  const c = input.config;
  uuid(c.dataSource);
  if (!c.fields.length || new Set(c.fields.map((f) => f.id)).size !== c.fields.length || new Set(c.fields.map((f) => f.property)).size !== c.fields.length)
    throw new Error("Invalid or duplicate Notion field mappings");
  const read = (operation, path, body) => parse(
    input.http(
      request(operation, body === void 0 ? "GET" : "POST", path, body)
    )
  );
  const schema = () => {
    const source = read("schema", `/data_sources/${c.dataSource}`);
    if (uuid(source.id) !== uuid(c.dataSource))
      throw new Error("Unexpected data source");
    for (const f of c.fields) {
      const p = Object.values(source.properties).find(
        (p2) => p2.id === f.id
      );
      if (!p || p.type !== f.type)
        throw new Error(`Mapped property ${f.id} changed type or was removed`);
      if (f.options) {
        const ids = (p[f.type]?.options ?? []).map((o) => o.id).sort();
        if (!equal2(ids, Object.keys(f.options).sort()))
          throw new Error(
            "Select options changed; refresh mapping before syncing"
          );
        for (const option of p[f.type].options) {
          if (f.optionNames && (option.name !== f.optionNames[option.id] || input.read(f.options[option.id])[P.name] !== f.optionNames[option.id]))
            throw new Error(
              "Select option names changed; review the mapping before syncing"
            );
        }
      }
    }
    return source;
  };
  const row = (subject) => {
    const value = input.read(subject);
    const binding = input.connection.records[`page:${value[c.identity]}`];
    return projectRow(value, c, binding?.baseline);
  };
  const page = (id) => {
    const p = read("page", `/pages/${uuid(id)}`);
    if (uuid(p.id) !== uuid(id)) throw new Error("Unexpected Notion page");
    return p;
  };
  const view = (id) => {
    const v = read("view", `/views/${uuid(id)}`);
    if (uuid(v.id) !== uuid(id)) throw new Error("Unexpected Notion view");
    return v;
  };
  const remote = (change) => change.kind === "page" ? projectPage(page(change.id), c) : change.kind === "view" ? projectView(view(change.id), c) : {
    name: Object.values(schema().properties).find(
      (p) => p.id === change.id
    ).name
  };
  const local = (change, subject = change.subject) => !subject ? void 0 : change.kind === "page" ? row(subject) : change.kind === "schema" ? { name: input.read(subject)[P.name] } : projectLocalView(
    input.read(subject),
    c,
    c.views.find((v) => v.id === change.id)
  );
  if (input.phase === "preview") {
    const source = schema();
    const proposal = {
      dataSource: c.dataSource,
      changes: [],
      conflicts: []
    };
    const add = (change) => {
      const key = change.id ? `${change.kind}:${change.id}` : void 0;
      const bound = key ? input.connection.records[key] : void 0;
      if (bound && bound.local !== change.subject) {
        proposal.conflicts.push({
          id: change.id,
          fields: ["Missing or rebound Atomic identity"]
        });
        return;
      }
      const decision = reconcileRecord(
        bound?.baseline,
        change.local,
        change.remote
      );
      if (decision.conflicts.length) {
        proposal.conflicts.push({
          id: change.id,
          fields: decision.conflicts.map((x) => x.property)
        });
        return;
      }
      proposal.changes.push({
        ...change,
        desired: {
          ...change.remote ?? change.local,
          ...decision.remote
        }
      });
    };
    for (const f of c.fields) {
      const p = Object.values(source.properties).find(
        (p2) => p2.id === f.id
      );
      add({
        kind: "schema",
        id: f.id,
        subject: f.property,
        local: { name: input.read(f.property)[P.name] },
        remote: { name: p.name }
      });
    }
    for (const v of c.views)
      add({
        kind: "view",
        id: v.id,
        subject: v.subject,
        local: local({
          kind: "view",
          id: v.id,
          subject: v.subject,
          desired: {}
        }),
        remote: projectView(view(v.id), c)
      });
    const rows = input.query(P.parent, c.table).filter((s) => input.read(s)[P.isA]?.includes(c.rowClass));
    const byId = /* @__PURE__ */ new Map();
    for (const s of rows) {
      const id = input.read(s)[c.identity];
      if (id) {
        uuid(id);
        if (byId.has(id)) throw new Error("Duplicate Notion page identity");
        byId.set(id, s);
      } else add({ kind: "page", subject: s, local: row(s) });
    }
    const seen = /* @__PURE__ */ new Set();
    const cursors = /* @__PURE__ */ new Set();
    let cursor2;
    for (let batch = 0; ; batch++) {
      if (batch >= 100) throw new Error("Notion pilot scan exceeds 100 pages");
      const result = read("query", `/data_sources/${c.dataSource}/query`, {
        page_size: 100,
        ...cursor2 ? { start_cursor: cursor2 } : {}
      });
      if (!Array.isArray(result.results) || typeof result.has_more !== "boolean")
        throw new Error("Invalid Notion query page");
      for (const p of result.results) {
        const id = uuid(p.id);
        if (seen.has(id))
          throw new Error("Duplicate page during scan; retry a stable read");
        seen.add(id);
        const subject = byId.get(id);
        add({
          kind: "page",
          id,
          subject,
          local: subject ? row(subject) : void 0,
          remote: projectPage(p, c)
        });
      }
      if (!result.has_more) break;
      if (typeof result.next_cursor !== "string" || !result.next_cursor || cursors.has(result.next_cursor))
        throw new Error("Incomplete or looping Notion pagination");
      cursor2 = result.next_cursor;
      cursors.add(cursor2);
    }
    for (const [id] of byId)
      if (!seen.has(id))
        proposal.conflicts.push({
          id,
          fields: ["Missing or inaccessible page; no deletion inferred"]
        });
    for (const key of Object.keys(input.connection.records))
      if (key.startsWith("page:") && !seen.has(key.slice(5)))
        proposal.conflicts.push({
          id: key.slice(5),
          fields: ["Previously synced page missing"]
        });
    return {
      kind: "preview",
      proposal,
      problems: proposal.conflicts.map((x) => ({
        severity: "error",
        message: `${x.id ?? "New row"}: ${x.fields.join(", ")}`
      }))
    };
  }
  if (!input.proposal || input.proposal.dataSource !== c.dataSource || input.proposal.conflicts.length)
    throw new Error("A conflict-free approved Notion preview is required");
  let cursor = input.cursor ?? { index: 0, stage: "start", records: [] };
  const effect = (value, next) => ({
    kind: "effect",
    effect: value,
    cursor: next
  });
  const external = (operation, path, body, next) => effect(
    {
      kind: "external",
      id: `${cursor.index}:remote`,
      request: request(
        operation,
        operation === "create" ? "POST" : "PATCH",
        path,
        body,
        `${cursor.index}:remote`
      )
    },
    next
  );
  for (let i = 0; i < 8; i++) {
    if (cursor.stage === "done") return { kind: "complete" };
    if (cursor.index === input.proposal.changes.length)
      return effect(
        { kind: "checkpoint", id: "checkpoint", records: cursor.records },
        { ...cursor, stage: "done" }
      );
    const change = input.proposal.changes[cursor.index];
    if (cursor.stage === "start") {
      schema();
      if (!equal2(local(change), change.local))
        throw new Error("Atomic data changed after preview");
      if (change.id && !equal2(remote(change), change.remote))
        throw new Error("Notion data changed after preview");
      cursor = {
        ...cursor,
        id: change.id,
        subject: change.subject,
        stage: "local"
      };
      if (change.kind === "page") {
        const properties = pagePatch(change.desired, change.remote, c);
        if (!change.id)
          return external(
            "create",
            "/pages",
            { parent: { data_source_id: c.dataSource }, properties },
            { ...cursor, stage: "created" }
          );
        if (Object.keys(properties).length)
          return external(
            "update",
            `/pages/${change.id}`,
            { properties },
            cursor
          );
      } else if (change.kind === "schema" && !equal2(change.desired, change.remote))
        return external(
          "rename",
          `/data_sources/${c.dataSource}`,
          { properties: { [change.id]: { name: change.desired.name } } },
          cursor
        );
      else if (change.kind === "view") {
        const patch = viewPatch(change.desired, view(change.id), c);
        if (Object.keys(patch).length)
          return external("view-update", `/views/${change.id}`, patch, cursor);
      }
    } else if (cursor.stage === "created") {
      const p = parse(input.result);
      projectPage(p, c);
      cursor = { ...cursor, id: uuid(p.id), stage: "local" };
    } else if (cursor.stage === "local") {
      const actual = { ...change, id: cursor.id };
      if (!equal2(remote(actual), change.desired))
        throw new Error(
          "Notion has not converged; keep the saved run for reconciliation"
        );
      const here = local(change, cursor.subject);
      if (!equal2(here, change.local) && !equal2(here, change.desired))
        throw new Error("Atomic data changed during sync");
      let set;
      let remove = [];
      if (change.kind === "page") {
        const matches = input.query(c.identity, cursor.id).filter((s) => input.read(s)[P.parent] === c.table);
        if (matches.some((s) => s !== cursor.subject))
          throw new Error("Unexpected page binding appeared during sync");
        ({ set, remove } = rowPatch(change.desired, c));
        Object.assign(
          set,
          claimImportIdentity(
            input,
            c.table,
            `notion:${uuid(c.dataSource)}:page:${uuid(cursor.id)}`,
            cursor.subject
          )
        );
        set[c.identity] = cursor.id;
        if (!cursor.subject && input.connection.revision > 0)
          set[c.arrival] = "remote";
      } else if (change.kind === "schema")
        set = { [P.name]: change.desired.name };
      else {
        set = {
          [P.name]: change.desired.name,
          [P.kind]: change.desired.kind === "board" ? "kanban" : "table",
          [P.columns]: change.desired.columns.map(
            (id) => c.fields.find((f) => f.id === id).property
          )
        };
        if (change.desired.group)
          set[P.group] = c.fields.find(
            (f) => f.id === change.desired.group
          ).property;
        else remove.push(P.group);
      }
      if (equal2(here, change.desired) && (change.kind !== "page" || input.read(cursor.subject)[c.identity] === cursor.id && input.read(cursor.subject)[IMPORT_LOCAL_ID] === `notion:${uuid(c.dataSource)}:page:${uuid(cursor.id)}` && input.read(cursor.subject)[P.name] === change.desired[c.fields.find((f) => f.type === "title").id]))
        cursor = { ...cursor, stage: "verify" };
      else {
        const intents = cursor.subject ? [
          { op: "set", subject: cursor.subject, set },
          ...remove.length ? [
            {
              op: "remove",
              subject: cursor.subject,
              properties: remove
            }
          ] : []
        ] : [
          {
            op: "create",
            localId: "row",
            parent: c.table,
            isA: [c.rowClass],
            set
          }
        ];
        return effect(
          {
            kind: "atomic",
            id: `${cursor.index}:atomic`,
            verdict: { intents, problems: [] }
          },
          { ...cursor, stage: "written" }
        );
      }
    } else if (cursor.stage === "written") {
      const subject = input.result.outcomes?.[0]?.subject;
      if (!subject) throw new Error("Missing Atomic receipt");
      cursor = { ...cursor, subject, stage: "verify" };
    } else if (cursor.stage === "verify") {
      const l = local(change, cursor.subject);
      const r = remote({ ...change, id: cursor.id });
      if (!equal2(l, change.desired) || !equal2(r, change.desired))
        throw new Error("Both sides must agree before checkpointing");
      cursor = {
        index: cursor.index + 1,
        stage: "start",
        records: [
          ...cursor.records,
          {
            remote: `${change.kind}:${cursor.id}`,
            local: cursor.subject,
            local_projection: l,
            remote_projection: r
          }
        ]
      };
      return { kind: "continue", cursor };
    } else throw new Error("Unknown Notion continuation");
  }
  throw new Error("Notion continuation exceeded transition budget");
}
export {
  run
};
