import { expect, it } from 'vitest';
import { clockifyUpgrade } from './clockifyUpgradeSource';
import { manifest } from '../../../../../integrations/clockify/model';
it('upgrades only JSON configured Clockify installs, retaining the exact settings', () => {
  const config = {
    workspace: 'a'.repeat(24),
    user: 'b'.repeat(24),
    drive: 'drive',
    table: 'table',
    properties: { identity: 'identity' },
  };
  const trailer = `\nconst settings=${JSON.stringify(config)};\nexport const manifest=${JSON.stringify(manifest(config.workspace, config.user))};`;
  expect(clockifyUpgrade('old' + trailer, 'new')).toBe('new' + trailer);
  expect(clockifyUpgrade('new' + trailer, 'new')).toBeUndefined();
  expect(
    clockifyUpgrade('const settings=executeSomething();', 'new'),
  ).toBeUndefined();
  expect(
    clockifyUpgrade('old' + trailer.replace('"clockify"', '"other"'), 'new'),
  ).toBeUndefined();
});
