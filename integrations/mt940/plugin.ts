// @wc-ignore-file
import {
  importRecords,
  type ImportRecord,
} from '../../browser/lib/src/import-records.js';
import { parseMT940 } from './parser.js';
export const manifest = { schemaVersion: 1, operations: [], secrets: [] };
export interface Config {
  table: string;
  rowClass: string;
  properties: Record<string, string>;
}
interface Host {
  text?: string;
  trigger?: { payload?: { text?: string; validate?: boolean } };
  config: Config;
  query(property: string, value: string): string[];
  read(subject: string): Record<string, unknown>;
}
export function run(ctx: Host) {
  const text = ctx.text ?? ctx.trigger?.payload?.text;
  if (!text)
    throw new Error(
      'Open Bank statements in Integrations and choose an MT940 file',
    );
  const statements = parseMT940(text);
  if (ctx.trigger?.payload?.validate) return { intents: [], problems: [] };
  const { table, rowClass, properties: p } = ctx.config;
  const records: ImportRecord[] = [];
  const seen = new Map<string, string>();
  let fallback = 0;
  for (const statement of statements) {
    const statementKey = JSON.stringify([
      statement.number,
      statement.start,
      statement.end,
      statement.opening,
      statement.closing,
    ]);
    for (const [index, row] of statement.transactions.entries()) {
      const fingerprint =
        'mt940-content:' +
        JSON.stringify([
          statement.account,
          statement.currency,
          row.date,
          row.bookingDate,
          row.amount,
          row.code,
          row.reference,
          row.description,
        ]);
      const reference =
        row.bankReference && row.bankReference !== 'NONREF'
          ? row.bankReference
          : '';
      const identity = JSON.stringify([
        'mt940',
        statement.account,
        statement.currency,
        reference ? ['bank', reference] : ['statement', statementKey, index],
      ]);
      if (seen.has(identity)) {
        if (seen.get(identity) !== fingerprint)
          throw new Error(
            'Conflicting bank transaction references in this file',
          );
        throw new Error(
          'Repeated bank transaction reference in this file; export non-overlapping statements',
        );
      }
      seen.set(identity, fingerprint);
      if (!reference) {
        fallback++;
        if (
          !ctx
            .query(p['bank-source-id'], identity)
            .some(
              subject =>
                ctx.read(subject)[
                  'https://atomicdata.dev/properties/parent'
                ] === table,
            ) &&
          ctx
            .query(p['bank-fingerprint'], fingerprint)
            .some(
              subject =>
                ctx.read(subject)[
                  'https://atomicdata.dev/properties/parent'
                ] === table,
            )
        )
          throw new Error(
            'This statement overlaps an earlier import without unique bank references. Use the original statement or export a non-overlapping period.',
          );
      }
      const values: Record<string, string> = {
        'https://atomicdata.dev/properties/name':
          row.description || row.reference,
        [p['bank-account']]: statement.account,
        [p['bank-currency']]: statement.currency,
        [p['bank-amount']]: row.amount,
        [p['bank-value-date']]: row.date,
        [p['bank-booking-date']]: row.bookingDate,
        [p['bank-description']]: row.description,
        [p['bank-reference']]: row.bankReference || row.reference,
        [p['bank-transaction-code']]: row.code,
        [p['bank-statement']]: statement.number,
        [p['bank-source-id']]: identity,
        [p['bank-fingerprint']]: fingerprint,
      };
      records.push({
        sourceId: identity,
        mode: 'append',
        legacy: { property: p['bank-source-id'], value: identity },
        localId: `transaction-${records.length}`,
        parent: table,
        isA: [rowClass],
        values,
      });
    }
  }
  const result = importRecords(ctx, records);
  return {
    intents: result.intents,
    problems: [
      ...result.problems,
      {
        severity: 'warning',
        message: `${statements.length} statements reconciled. ${result.summary.unchanged} previously imported transactions skipped. Amounts are exact decimal strings; negative amounts are money out.`,
      },
      ...(fallback
        ? [
            {
              severity: 'warning',
              message:
                'Some transactions lack unique bank references. Reimporting the same statement is safe; ambiguous overlapping exports are blocked.',
            },
          ]
        : []),
    ],
  };
}
