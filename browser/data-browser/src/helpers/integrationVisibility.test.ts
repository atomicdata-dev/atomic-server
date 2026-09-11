import { describe, expect, it } from 'vitest';
import {
  integrationVisibility,
  integrationVisibilitySchema,
} from './integrationVisibility';

const properties = {
  'show-api-plugins': 'did:ad:api-preference',
  'show-experimental-plugins': 'did:ad:experimental-preference',
};

describe('Atomic integration visibility preferences', () => {
  it('defaults to hidden before schema hydration without writing defaults', () => {
    expect(integrationVisibility({ get: () => true })).toEqual({
      showApiPlugins: false,
      showExperimentalPlugins: false,
    });
  });

  it.each([undefined, false, 'true', 1, null])(
    'does not opt in for %s',
    value => {
      expect(integrationVisibility({ get: () => value }, properties)).toEqual({
        showApiPlugins: false,
        showExperimentalPlugins: false,
      });
    },
  );

  it.each([
    [false, false],
    [true, false],
    [false, true],
    [true, true],
  ])('keeps API=%s and experimental=%s independent', (api, experimental) => {
    const values = {
      [properties['show-api-plugins']]: api,
      [properties['show-experimental-plugins']]: experimental,
    };
    expect(
      integrationVisibility({ get: key => values[key] }, properties),
    ).toEqual({
      showApiPlugins: api,
      showExperimentalPlugins: experimental,
    });
  });

  it('defines both preferences as Atomic boolean properties', () => {
    expect(
      integrationVisibilitySchema().properties.map(p => [
        p.shortname,
        p.datatype,
      ]),
    ).toEqual([
      ['show-api-plugins', 'https://atomicdata.dev/datatypes/boolean'],
      ['show-experimental-plugins', 'https://atomicdata.dev/datatypes/boolean'],
    ]);
  });
});
