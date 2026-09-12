// @wc-ignore-file
import source from '../../../../../integrations/github-issues/plugin.js?raw';
import { install } from '../../../../../integrations/github-issues/atomic';
import type { Store } from '@tomic/lib';

export function installGitHub(
  store: Store,
  drive: string,
  repository: string,
  token: string,
  destination?: string,
) {
  return install(store, drive, repository, source, token, destination);
}
