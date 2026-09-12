// @wc-ignore-file
import source from '../../../../../integrations/notion/plugin.js?raw';
import { install } from '../../../../../integrations/notion/atomic';
import type { Store } from '@tomic/lib';

export function installNotion(
  store: Store,
  drive: string,
  dataSource: string,
  token: string | { connection: string },
) {
  return install(store, drive, dataSource, source, token);
}
