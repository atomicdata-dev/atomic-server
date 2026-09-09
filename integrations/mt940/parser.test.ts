import { describe, expect, it } from 'vitest';
import { parseMT940 } from './parser';
import { run } from './plugin';
export const fixture = `:20:SYNTHETIC
:25:NL00BUNQ0000000000
:28C:1/1
:60F:C260901EUR100,00
:61:2609020902D12,34NTRFNONREF//TEST-1
:86:Lunch
Second line
:61:2609030903C20,00NTRFNONREF//TEST-2
:86:Refund
:62F:C260903EUR107,66
`;
const p = Object.fromEntries(
  [
    'account',
    'currency',
    'amount',
    'value-date',
    'booking-date',
    'description',
    'reference',
    'transaction-code',
    'statement',
    'source-id',
    'fingerprint',
  ].map(k => [`bank-${k}`, `https://example.com/${k}`]),
);
const config = {
  table: 'https://example.com/table',
  rowClass: 'https://example.com/transaction',
  properties: p,
};
const host = {
  text: fixture,
  config,
  query: () => [] as string[],
  read: () => ({}),
};
describe('MT940 parser and import proposals', () => {
  it('rejects JSON-shaped narratives rather than letting legacy persistence reinterpret text', () => {
    expect(() =>
      parseMT940(fixture.replace('Lunch\nSecond line', '["literal text"]')),
    ).toThrow('JSON-shaped');
  });
  it('preserves exact debits, credits, dates and multiline descriptions', () => {
    const [statement] = parseMT940(fixture.replace(/\n/g, '\r\n'));
    expect(statement.transactions[0]).toMatchObject({
      amount: '-12.34',
      date: '2026-09-02',
      description: 'Lunch\nSecond line',
    });
    expect(statement.closing).toBe('107.66');
  });
  it('reconciles reversals and large exact amounts', () => {
    const sample = fixture
      .replace('D12,34', 'RC12,34')
      .replace('C20,00N', 'RD20,00N');
    expect(parseMT940(sample)[0].transactions.map(t => t.amount)).toEqual([
      '-12.34',
      '20',
    ]);
    expect(
      parseMT940(
        fixture
          .replace('EUR100,00', 'EUR900719925474099,00')
          .replace('EUR107,66', 'EUR900719925474106,66'),
      )[0].closing,
    ).toBe('900719925474106.66');
  });
  it('rejects wrong balances, invalid dates, truncation and unsupported fields', () => {
    for (const invalid of [
      fixture.replace('107,66', '107,67'),
      fixture.replace('260902', '260230'),
      fixture.split(':62F:')[0],
      fixture + ':99:unknown',
    ])
      expect(() => parseMT940(invalid)).toThrow();
  });
  it('supports multiple accounts and booking year rollover', () => {
    expect(
      parseMT940(fixture + fixture.replace('0000000000', '0000000001')),
    ).toHaveLength(2);
    expect(
      parseMT940(fixture.replace('2609020902', '2601011231'))[0].transactions[0]
        .bookingDate,
    ).toBe('2025-12-31');
  });
  it('nests rows under the table and skips identical reimports', () => {
    const verdict = run(host);
    const first = verdict.intents[0] as any;
    expect(first.parent).toBe(config.table);
    expect(first.set[p['bank-amount']]).toBe('-12.34');
    const saved = new Map(
      (verdict.intents as any[]).map((i, n) => [
        String(n),
        {
          ...i.set,
          'https://atomicdata.dev/properties/parent': i.parent,
          'https://atomicdata.dev/properties/isA': i.isA,
        },
      ]),
    );
    expect(
      run({
        ...host,
        query: (prop, value) =>
          [...saved].filter(([, v]) => v[prop] === value).map(([id]) => id),
        read: id => saved.get(id)!,
      }).intents,
    ).toHaveLength(0);
  });
  it('blocks changed referenced transactions and ambiguous reference-free overlap', () => {
    const first = run(host).intents[0] as any;
    const saved = {
      ...first.set,
      'https://atomicdata.dev/properties/parent': config.table,
      'https://atomicdata.dev/properties/isA': [config.rowClass],
    };
    const changed = run({
      ...host,
      text: fixture.replace('Lunch', 'Changed lunch'),
      query: (property, value) => (saved[property] === value ? ['saved'] : []),
      read: () => saved,
    });
    expect(changed.problems.some(p => p.severity === 'error')).toBe(true);
    expect(() =>
      run({
        ...host,
        text: fixture.replace(/\/\/TEST-\d/g, ''),
        query: prop => (prop === p['bank-fingerprint'] ? ['saved'] : []),
        read: () => ({
          'https://atomicdata.dev/properties/parent': config.table,
        }),
      }),
    ).toThrow('overlaps');
  });
  it('preserves identical legitimate reference-free transactions within one statement', () => {
    const sample = fixture
      .replace(/\/\/TEST-\d/g, '')
      .replace(
        ':62F:C260903EUR107,66',
        ':61:2609020902D12,34NTRFNONREF\n:86:Lunch\nSecond line\n:62F:C260903EUR95,32',
      );
    expect(run({ ...host, text: sample }).intents).toHaveLength(3);
  });
  it('bounds files and transaction counts', () => {
    expect(() => parseMT940('x'.repeat(512001))).toThrow('512 KB');
    expect(() =>
      parseMT940(
        ':25:test\n:28C:1\n:60F:C260901EUR0,\n' +
          ':61:260901C0,NTRFNONREF\n'.repeat(501) +
          ':62F:C260901EUR0,',
      ),
    ).toThrow('500');
  });
});
