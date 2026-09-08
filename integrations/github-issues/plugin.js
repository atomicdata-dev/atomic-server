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
function claimImportIdentity(host, parent2, sourceId, subject) {
  const matches = host.query(IMPORT_LOCAL_ID, sourceId).filter((id) => pure(host.read(id)[PARENT]) === pure(parent2));
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
function reconcileRecord(base, local, remote) {
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
    if (equal(local, base) && remote === null) result.deleteLocal = true;
    else if (equal(remote, base) && local === null) result.deleteRemote = true;
    else
      result.conflicts.push({
        property: "@record",
        base,
        local,
        remote
      });
    return result;
  }
  if (base !== void 0 && (local === void 0 || remote === void 0))
    return result;
  result.createLocal = base === void 0 && local === void 0 && remote !== void 0;
  result.createRemote = base === void 0 && remote === void 0 && local !== void 0;
  const properties = /* @__PURE__ */ new Set([
    ...Object.keys(base ?? {}),
    ...Object.keys(local ?? {}),
    ...Object.keys(remote ?? {})
  ]);
  for (const property of properties) {
    const before = base?.[property];
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

// integrations/github-issues/adapter.ts
var headers = {
  Accept: "application/vnd.github+json",
  "User-Agent": "Atomic-GitHub-Issues-Pilot",
  "X-GitHub-Api-Version": "2022-11-28",
  Authorization: "secret:github",
  "Content-Type": "application/json"
};
function project(issue) {
  if (!Number.isSafeInteger(issue.number) || issue.number <= 0 || typeof issue.title !== "string" || !(issue.body === null || typeof issue.body === "string") || !["open", "closed"].includes(issue.state) || !Array.isArray(issue.labels))
    throw new Error("GitHub returned an invalid issue");
  return {
    title: issue.title,
    body: issue.body ?? "",
    status: issue.state === "closed" ? "Done" : issue.labels.some(
      (l) => (typeof l === "string" ? l : l.name).toLowerCase() === "atomic:doing"
    ) ? "Doing" : "Todo"
  };
}
function validate(value) {
  if (typeof value.title !== "string" || !value.title.trim() || typeof value.body !== "string" || !["Todo", "Doing", "Done"].includes(value.status))
    throw new Error(
      "Cards require a title, Markdown body and exactly one Todo/Doing/Done status"
    );
}
function endpoint(repository) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository) || repository.split("/").some((p) => p === "." || p === ".."))
    throw new Error("Repository must be owner/name");
  return `https://api.github.com/repos/${repository}/issues`;
}
function parse(response) {
  if (response.status < 200 || response.status >= 300)
    throw new Error(
      `GitHub returned ${response.status}; no checkpoint was advanced. Resolve access/rate limits before retrying.`
    );
  return JSON.parse(response.body);
}
function request(operation, method, url, id, body) {
  return {
    operation,
    method,
    url,
    id,
    headers,
    ...body === void 0 ? {} : { body: JSON.stringify(body) }
  };
}
async function preview(host, repository) {
  const root = endpoint(repository);
  const state = await host.state();
  if (state.cursor)
    throw new Error(
      "A saved sync is pending; resume it before previewing another run"
    );
  const issues = /* @__PURE__ */ new Map();
  for (let page = 1; ; page++) {
    if (page > 100)
      throw new Error("Pilot supports at most 10,000 issues/PRs per scan");
    const rows = parse(
      await host.read(
        request(
          "list",
          "GET",
          `${root}?state=all&per_page=100&page=${page}&sort=created&direction=asc`,
          `page-${page}`
        )
      )
    );
    if (!Array.isArray(rows))
      throw new Error("GitHub issue page must be an array");
    for (const issue of rows)
      if (!("pull_request" in issue)) {
        project(issue);
        issues.set(issue.number, issue);
      }
    if (rows.length < 100) break;
  }
  const cards = await host.cards();
  const byNumber = /* @__PURE__ */ new Map();
  for (const card of cards) {
    validate(card.value);
    if (card.number !== void 0) {
      if (byNumber.has(card.number))
        throw new Error(`Duplicate cards for issue #${card.number}`);
      byNumber.set(card.number, card);
    }
  }
  const result = {
    repository,
    revision: state.revision,
    changes: [],
    conflicts: []
  };
  for (const [number, issue] of issues) {
    const remote = project(issue);
    const binding = state.records[String(number)];
    const card = byNumber.get(number);
    if (binding && (!card || binding.local !== card.subject)) {
      result.conflicts.push({
        number,
        fields: ["Missing or rebound local card"]
      });
      continue;
    }
    const decision = reconcileRecord(
      binding?.baseline,
      card?.value,
      remote
    );
    if (decision.conflicts.length) {
      result.conflicts.push({
        subject: card?.subject,
        number,
        fields: decision.conflicts.map((c) => c.property)
      });
      continue;
    }
    const desired = { ...remote, ...decision.remote };
    validate(desired);
    result.changes.push({
      subject: card?.subject,
      number,
      local: card?.value,
      remote,
      desired
    });
  }
  for (const card of cards) {
    if (card.number === void 0)
      result.changes.push({
        subject: card.subject,
        local: card.value,
        desired: card.value
      });
    else if (!issues.has(card.number))
      result.conflicts.push({
        subject: card.subject,
        number: card.number,
        fields: ["Issue missing or inaccessible; no deletion inferred"]
      });
  }
  return result;
}

// integrations/github-issues/plugin.ts
var parent = "https://atomicdata.dev/properties/parent";
var isA = "https://atomicdata.dev/properties/isA";
var name = "https://atomicdata.dev/properties/name";
globalThis.structuredClone ??= ((value) => value === void 0 ? void 0 : JSON.parse(JSON.stringify(value)));
var equal2 = (a, b) => a === b || !!a && !!b && a.title === b.title && a.body === b.body && a.status === b.status;
async function run(input) {
  const config = input.config;
  if (input.phase === "action") {
    const root2 = endpoint(config.repository);
    const args = input.arguments ?? {};
    if (input.action === "get_issue") {
      if (!Number.isSafeInteger(args.number) || Number(args.number) <= 0)
        throw new Error("Choose a positive issue number");
      return request("get", "GET", `${root2}/${args.number}`, "action");
    }
    if (input.action === "create_issue") {
      if (typeof args.title !== "string" || !args.title.trim() || args.title.length > 256)
        throw new Error("Issue title must contain 1 to 256 characters");
      return request("create", "POST", root2, "action", {
        title: args.title,
        body: args.body ?? ""
      });
    }
    throw new Error("Unknown integration action");
  }
  if (!config || !config.table || !config.rowClass || !config.tags || Object.keys(config.tags).length !== 3)
    throw new Error("Configure the connection before running it");
  const root = endpoint(config.repository);
  const card = (subject) => {
    const row = input.read(subject);
    if (!row[isA]?.includes(config.rowClass) || row[parent] !== config.table)
      return;
    const selected = row[config.status];
    const status = selected?.length ? Object.entries(config.tags).find(
      ([, id]) => selected.length === 1 && selected[0] === id
    )?.[0] : "Todo";
    if (!status) throw new Error("Choose exactly one kanban status");
    const number = row[config.number];
    if (number !== void 0 && (!Number.isSafeInteger(number) || Number(number) <= 0))
      throw new Error("Invalid GitHub issue number");
    return {
      subject,
      ...number === void 0 ? {} : { number },
      value: {
        title: String(row[name] ?? ""),
        body: String(row[config.body] ?? ""),
        status
      }
    };
  };
  const find = (number) => {
    const matches = input.query(config.number, String(number)).map(card).filter((r) => r !== void 0);
    if (matches.length > 1) throw new Error("Duplicate issue identity");
    return matches[0];
  };
  const issue = (number) => {
    const response = input.http(
      request("get", "GET", `${root}/${number}`, "read")
    );
    if (response.status !== 200)
      throw new Error(
        `GitHub read failed (${response.status}); no deletion inferred`
      );
    const value = JSON.parse(response.body);
    if ("pull_request" in value || value.number !== number)
      throw new Error("Expected the selected issue");
    project(value);
    return value;
  };
  if (input.phase === "preview") {
    const proposal = await preview(
      {
        read: async (intent) => input.http(intent),
        state: async () => input.connection,
        cards: async () => input.query(parent, config.table).map(card).filter((r) => r !== void 0)
      },
      config.repository
    );
    return {
      kind: "preview",
      proposal,
      problems: proposal.conflicts.map((c) => ({
        severity: "error",
        message: `Issue ${c.number ?? c.subject}: ${c.fields.join(", ")}`
      }))
    };
  }
  if (!input.proposal || input.proposal.repository !== config.repository || input.proposal.conflicts.length)
    throw new Error("An approved conflict-free proposal is required");
  let cursor = input.cursor ?? {
    index: 0,
    stage: "start",
    records: []
  };
  const effect = (value, next) => ({
    kind: "effect",
    effect: value,
    cursor: next
  });
  const external = (operation, method, url, suffix, next, body) => {
    const id = `${cursor.index}:${suffix}`;
    return effect(
      {
        kind: "external",
        id,
        request: request(operation, method, url, id, body)
      },
      next
    );
  };
  for (let transitions = 0; transitions < 12; transitions++) {
    if (cursor.stage === "done") return { kind: "complete" };
    if (cursor.index === input.proposal.changes.length)
      return effect(
        { kind: "checkpoint", id: "checkpoint", records: cursor.records },
        { ...cursor, stage: "done" }
      );
    const change = input.proposal.changes[cursor.index];
    const desired = change.desired;
    if (cursor.stage === "start") {
      const local = change.subject ? card(change.subject) : change.number ? find(change.number) : void 0;
      if (change.subject && (!local || !equal2(local.value, change.local)))
        throw new Error("Card changed after preview");
      if (!change.subject && local)
        throw new Error("An imported card appeared after preview");
      if (change.number && local && local.number !== change.number)
        throw new Error("Card identity changed after preview");
      if (change.number === void 0)
        return external(
          "create",
          "POST",
          root,
          "create",
          { ...cursor, stage: "created", subject: local?.subject },
          {
            title: desired.title,
            body: desired.body,
            labels: desired.status === "Doing" ? ["atomic:doing"] : []
          }
        );
      const remote = project(issue(change.number));
      if (!equal2(remote, change.remote))
        throw new Error("Issue changed after preview");
      cursor = {
        ...cursor,
        stage: "patch",
        number: change.number,
        subject: local?.subject
      };
    } else if (cursor.stage === "created") {
      const created = JSON.parse(input.result.body);
      project(created);
      cursor = { ...cursor, number: created.number, stage: "patch" };
    } else if (cursor.stage === "patch") {
      const patch = {};
      if (change.remote && change.remote.title !== desired.title)
        patch.title = desired.title;
      if (change.remote && change.remote.body !== desired.body)
        patch.body = desired.body;
      if (!change.remote && desired.status === "Done" || change.remote && change.remote.status === "Done" !== (desired.status === "Done"))
        patch.state = desired.status === "Done" ? "closed" : "open";
      const next = { ...cursor, stage: "labels" };
      if (Object.keys(patch).length)
        return external(
          "update",
          "PATCH",
          `${root}/${cursor.number}`,
          "update",
          next,
          patch
        );
      cursor = next;
    } else if (cursor.stage === "labels") {
      const current = issue(cursor.number);
      const doing = current.labels.some(
        (l) => (typeof l === "string" ? l : l.name).toLowerCase() === "atomic:doing"
      );
      const next = { ...cursor, stage: "local" };
      if (desired.status === "Doing" && !doing)
        return external(
          "doing-add",
          "POST",
          `${root}/${cursor.number}/labels`,
          "label",
          next,
          {
            labels: ["atomic:doing"]
          }
        );
      if (desired.status !== "Doing" && doing)
        return external(
          "doing-remove",
          "DELETE",
          `${root}/${cursor.number}/labels/atomic%3Adoing`,
          "label",
          next
        );
      cursor = next;
    } else if (cursor.stage === "local") {
      if (!equal2(project(issue(cursor.number)), desired))
        throw new Error("GitHub did not converge; checkpoint paused");
      const local = cursor.subject ? card(cursor.subject) : find(cursor.number);
      if (cursor.subject && (!local || !equal2(local.value, change.local) && !equal2(local.value, desired)))
        throw new Error("Card changed during sync");
      if (!cursor.subject && local)
        throw new Error(
          "An unexpected card appeared; reconcile before creating"
        );
      const identity = `github:${config.repository.toLowerCase()}:issue:${cursor.number}`;
      const set = {
        ...claimImportIdentity(input, config.table, identity, local?.subject),
        [name]: desired.title,
        [config.body]: desired.body,
        [config.status]: [config.tags[desired.status]],
        [config.number]: cursor.number,
        ...config.arrival && !local && change.remote && input.connection.revision > 0 ? { [config.arrival]: "remote" } : {}
      };
      if (local && equal2(local.value, desired) && local.number === cursor.number && input.read(local.subject)[IMPORT_LOCAL_ID] === identity)
        cursor = { ...cursor, subject: local.subject, stage: "verify" };
      else
        return effect(
          {
            kind: "atomic",
            id: `${cursor.index}:card`,
            verdict: {
              intents: [
                local ? { op: "set", subject: local.subject, set } : {
                  op: "create",
                  localId: "card",
                  parent: config.table,
                  isA: [config.rowClass],
                  set
                }
              ],
              problems: []
            }
          },
          { ...cursor, stage: "written" }
        );
    } else if (cursor.stage === "written") {
      const subject = input.result.outcomes?.[0]?.subject;
      if (!subject) throw new Error("Atomic receipt is missing its subject");
      cursor = { ...cursor, subject, stage: "verify" };
    } else if (cursor.stage === "verify") {
      const local = card(cursor.subject);
      const remote = project(issue(cursor.number));
      if (!local || local.number !== cursor.number || !equal2(local.value, desired) || !equal2(remote, desired))
        throw new Error("Both sides must agree before checkpointing");
      cursor = {
        index: cursor.index + 1,
        stage: "start",
        records: [
          ...cursor.records,
          {
            remote: String(cursor.number),
            local: local.subject,
            local_projection: local.value,
            remote_projection: remote
          }
        ]
      };
      return { kind: "continue", cursor };
    } else throw new Error("Unknown connection continuation");
  }
  throw new Error("Too many pure transitions");
}
export {
  run
};
