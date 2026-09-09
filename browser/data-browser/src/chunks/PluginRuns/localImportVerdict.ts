// @wc-ignore-file
import { core, type Store } from '@tomic/react';
import {
  run,
  type Config,
} from '../../../../../integrations/localthought/plugin';

/** The shipped pure mapper gets a local read snapshot, never network or credentials. */
export async function localImportRows(
  store: Store,
  drive: string,
  config: Config,
) {
  const rows = new Map<string, Record<string, unknown>>();
  for (const { table } of Object.values(config.destinations)) {
    let offset = 0;
    for (;;) {
      const result = await store.queryLocalDb({
        drive,
        property: core.properties.parent,
        value: table,
        offset,
        limit: 1000,
      });
      if (!result)
        throw new Error('Local database must be available before importing');
      for (const subject of result.subjects)
        rows.set(subject, (await store.getResource(subject)).getPropVals());
      offset += result.subjects.length;
      if (offset >= result.count) break;
      if (!result.subjects.length)
        throw new Error('Local import snapshot is incomplete');
    }
  }
  return rows;
}

export async function localImportVerdict(
  store: Store,
  drive: string,
  config: Config,
) {
  const rows = await localImportRows(store, drive, config);
  return JSON.stringify(
    run({
      config,
      query: (property, value) =>
        [...rows]
          .filter(([, row]) => row[property] === value)
          .map(([subject]) => subject),
      read: subject => {
        const row = rows.get(subject);
        if (!row) throw new Error('Missing local import record');
        return row;
      },
    }),
  );
}
