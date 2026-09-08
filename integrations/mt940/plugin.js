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

// integrations/mt940/parser.ts
function decimal(raw, negative = false) {
  if (!/^\d{1,15},\d{0,5}$/.test(raw)) throw new Error("Invalid MT940 amount");
  const [whole, fraction = ""] = raw.split(",");
  const value = `${whole.replace(/^0+(?=\d)/, "")}${fraction.replace(/0+$/, "") ? "." + fraction.replace(/0+$/, "") : ""}`;
  return negative && value !== "0" ? "-" + value : value;
}
function units(value) {
  const negative = value.startsWith("-");
  const [whole, fraction = ""] = value.replace(/^-/, "").split(".");
  return BigInt(whole + fraction.padEnd(5, "0")) * (negative ? -1n : 1n);
}
function date(raw) {
  const year = Number(raw.slice(0, 2));
  const full = year >= 70 ? 1900 + year : 2e3 + year;
  const result = `${full}-${raw.slice(2, 4)}-${raw.slice(4, 6)}`;
  const parsed = /* @__PURE__ */ new Date(result + "T00:00:00Z");
  if (!/^\d{6}$/.test(raw) || !Number.isFinite(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== result)
    throw new Error("Invalid MT940 date");
  return result;
}
function balance(value) {
  const match = value.match(/^([CD])(\d{6})([A-Z]{3})(\d+,\d*)$/);
  if (!match) throw new Error("Invalid MT940 balance");
  return {
    date: date(match[2]),
    currency: match[3],
    amount: decimal(match[4], match[1] === "D")
  };
}
function transaction(value) {
  const [line, ...extra] = value.split("\n");
  const match = line.match(
    /^(\d{6})(\d{4})?(RC|RD|C|D)([A-Z])?(\d+,\d*)([NSF][A-Z0-9]{3})(.*)$/
  );
  if (!match) throw new Error("Unsupported MT940 transaction line");
  const valueDate = date(match[1]);
  let bookingDate = valueDate;
  if (match[2]) {
    const valueYear = Number(valueDate.slice(0, 4));
    const month = Number(match[2].slice(0, 2));
    const valueMonth = Number(valueDate.slice(5, 7));
    const year = valueYear + (month - valueMonth > 6 ? -1 : valueMonth - month > 6 ? 1 : 0);
    bookingDate = date(String(year % 100).padStart(2, "0") + match[2]);
  }
  const [reference, bankReference = "", ...unexpected] = match[7].split("//");
  if (!reference || unexpected.length)
    throw new Error("Invalid MT940 transaction reference");
  return {
    date: valueDate,
    bookingDate,
    amount: decimal(match[5], match[3] === "D" || match[3] === "RC"),
    code: match[6],
    reference,
    bankReference,
    description: extra.join("\n")
  };
}
function parseMT940(text) {
  if (typeof text !== "string" || text.length > 512e3)
    throw new Error("Choose an MT940 file smaller than 512 KB");
  const normalized = text.replace(/^\uFEFF/, "").replace(/\r\n?/g, "\n").trim();
  const fields = [];
  for (const line of normalized.split("\n")) {
    if (/^(?:\{1:.*\{4:|\{4:| -\}|-\}|\{5:.*\})$/.test(line)) continue;
    const match = line.match(/^:(\d{2}[A-Z]?):(.*)$/);
    if (match) fields.push({ tag: match[1], value: match[2] });
    else if (line.trim()) {
      const previous = fields[fields.length - 1];
      if (!previous || !["61", "86"].includes(previous.tag))
        throw new Error("Unsupported MT940 header or field continuation");
      previous.value += "\n" + line;
    }
  }
  const statements = [];
  let account = "", number = "", current;
  let closed = true, count = 0;
  for (const { tag, value } of fields) {
    switch (tag) {
      case "20":
        if (!closed)
          throw new Error("Statement is missing its closing balance");
        account = "";
        number = "";
        current = void 0;
        break;
      case "21":
        break;
      case "25":
        if (!closed) throw new Error("Unexpected account inside a statement");
        account = value.trim();
        if (!account) throw new Error("Missing bank account");
        break;
      case "28":
      case "28C":
        if (!closed) throw new Error("Unexpected statement number");
        number = value.trim();
        break;
      case "60F":
      case "60M": {
        if (!closed || !account || !number)
          throw new Error("Missing or out-of-order MT940 statement fields");
        const opening = balance(value);
        current = {
          account,
          number,
          currency: opening.currency,
          opening: opening.amount,
          closing: "",
          start: opening.date,
          end: "",
          transactions: []
        };
        statements.push(current);
        closed = false;
        break;
      }
      case "61":
        if (!current || closed)
          throw new Error("Transaction outside an open statement");
        if (++count > 500)
          throw new Error(
            "Import at most 500 transactions at a time; export a shorter period"
          );
        current.transactions.push(transaction(value));
        break;
      case "86": {
        if (!current || closed)
          throw new Error("Unsupported statement-level narrative");
        const row = current.transactions[current.transactions.length - 1];
        if (!row) throw new Error("Narrative without a transaction");
        row.description = [row.description, value].filter(Boolean).join("\n");
        break;
      }
      case "62F":
      case "62M": {
        if (!current || closed)
          throw new Error("Closing balance without an open statement");
        const closing = balance(value);
        if (closing.currency !== current.currency || closing.date < current.start)
          throw new Error("Statement currency or date range is inconsistent");
        if (units(current.opening) + current.transactions.reduce(
          (sum, row) => sum + units(row.amount),
          0n
        ) !== units(closing.amount))
          throw new Error(
            "Statement balance does not reconcile; no transactions will be imported"
          );
        current.closing = closing.amount;
        current.end = closing.date;
        closed = true;
        break;
      }
      case "64":
      case "65":
        balance(value);
        break;
      default:
        throw new Error(`Unsupported MT940 field :${tag}:`);
    }
  }
  if (!statements.length || !closed)
    throw new Error(
      "Incomplete MT940 statement: opening and closing balances are required"
    );
  for (const statement of statements)
    for (const row of statement.transactions) {
      const narrative = row.description.trim();
      if (narrative.startsWith("[") || narrative.startsWith("{")) {
        let parsed;
        try {
          parsed = JSON.parse(narrative);
        } catch {
          continue;
        }
        if (parsed && typeof parsed === "object")
          throw new Error(
            "JSON-shaped bank narratives are not supported yet; the statement was not imported"
          );
      }
    }
  return statements;
}

// integrations/mt940/plugin.ts
var manifest = { schemaVersion: 1, operations: [], secrets: [] };
function run(ctx) {
  const text = ctx.text ?? ctx.trigger?.payload?.text;
  if (!text)
    throw new Error(
      "Open Bank statements in Integrations and choose an MT940 file"
    );
  const statements = parseMT940(text);
  if (ctx.trigger?.payload?.validate) return { intents: [], problems: [] };
  const { table, rowClass, properties: p } = ctx.config;
  const records = [];
  const seen = /* @__PURE__ */ new Map();
  let fallback = 0;
  for (const statement of statements) {
    const statementKey = JSON.stringify([
      statement.number,
      statement.start,
      statement.end,
      statement.opening,
      statement.closing
    ]);
    for (const [index, row] of statement.transactions.entries()) {
      const fingerprint = "mt940-content:" + JSON.stringify([
        statement.account,
        statement.currency,
        row.date,
        row.bookingDate,
        row.amount,
        row.code,
        row.reference,
        row.description
      ]);
      const reference = row.bankReference && row.bankReference !== "NONREF" ? row.bankReference : "";
      const identity = JSON.stringify([
        "mt940",
        statement.account,
        statement.currency,
        reference ? ["bank", reference] : ["statement", statementKey, index]
      ]);
      if (seen.has(identity)) {
        if (seen.get(identity) !== fingerprint)
          throw new Error(
            "Conflicting bank transaction references in this file"
          );
        throw new Error(
          "Repeated bank transaction reference in this file; export non-overlapping statements"
        );
      }
      seen.set(identity, fingerprint);
      if (!reference) {
        fallback++;
        if (!ctx.query(p["bank-source-id"], identity).some(
          (subject) => ctx.read(subject)["https://atomicdata.dev/properties/parent"] === table
        ) && ctx.query(p["bank-fingerprint"], fingerprint).some(
          (subject) => ctx.read(subject)["https://atomicdata.dev/properties/parent"] === table
        ))
          throw new Error(
            "This statement overlaps an earlier import without unique bank references. Use the original statement or export a non-overlapping period."
          );
      }
      const values = {
        "https://atomicdata.dev/properties/name": row.description || row.reference,
        [p["bank-account"]]: statement.account,
        [p["bank-currency"]]: statement.currency,
        [p["bank-amount"]]: row.amount,
        [p["bank-value-date"]]: row.date,
        [p["bank-booking-date"]]: row.bookingDate,
        [p["bank-description"]]: row.description,
        [p["bank-reference"]]: row.bankReference || row.reference,
        [p["bank-transaction-code"]]: row.code,
        [p["bank-statement"]]: statement.number,
        [p["bank-source-id"]]: identity,
        [p["bank-fingerprint"]]: fingerprint
      };
      records.push({
        sourceId: identity,
        mode: "append",
        legacy: { property: p["bank-source-id"], value: identity },
        localId: `transaction-${records.length}`,
        parent: table,
        isA: [rowClass],
        values
      });
    }
  }
  const result = importRecords(ctx, records);
  return {
    intents: result.intents,
    problems: [
      ...result.problems,
      {
        severity: "warning",
        message: `${statements.length} statements reconciled. ${result.summary.unchanged} previously imported transactions skipped. Amounts are exact decimal strings; negative amounts are money out.`
      },
      ...fallback ? [
        {
          severity: "warning",
          message: "Some transactions lack unique bank references. Reimporting the same statement is safe; ambiguous overlapping exports are blocked."
        }
      ] : []
    ]
  };
}
export {
  manifest,
  run
};
