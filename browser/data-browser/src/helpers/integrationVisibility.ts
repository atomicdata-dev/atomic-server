// @wc-ignore-file
import { Datatype, type SchemaSpec } from '@tomic/lib';

/** Preferences live on the user's private drive, with properties in its ontology. */
export function integrationVisibilitySchema(): SchemaSpec {
  return {
    properties: [
      {
        shortname: 'show-api-plugins',
        name: 'Show API plugins',
        description:
          'Offer API plugins in integration discovery. Defaults to false.',
        datatype: Datatype.BOOLEAN,
      },
      {
        shortname: 'show-experimental-plugins',
        name: 'Show experimental plugins',
        description:
          'Offer experimental bundled and community plugins in integration discovery. Defaults to false.',
        datatype: Datatype.BOOLEAN,
      },
    ],
    classes: [],
  };
}

export type IntegrationVisibilityKey =
  | 'show-api-plugins'
  | 'show-experimental-plugins';

/** Only an explicit boolean opt-in enables discovery, including during loading. */
export function integrationVisibility(
  resource: { get(property: string): unknown },
  properties: Record<string, string> = {},
) {
  return {
    showApiPlugins:
      !!properties['show-api-plugins'] &&
      resource.get(properties['show-api-plugins']) === true,
    showExperimentalPlugins:
      !!properties['show-experimental-plugins'] &&
      resource.get(properties['show-experimental-plugins']) === true,
  };
}
