import { Datatype } from './datatypes.js';
import type { SchemaSpec } from './plugin-schema.js';

/** Shared within a drive until frozen schema package distribution lands. */
export function timeTrackingSchema(): SchemaSpec {
  return {
    properties: [
      {
        shortname: 'work-start',
        name: 'Start',
        datatype: Datatype.TIMESTAMP,
        description:
          'Start instant of a work interval, milliseconds since Unix epoch.',
      },
      {
        shortname: 'work-end',
        name: 'End',
        datatype: Datatype.TIMESTAMP,
        description:
          'End instant of a completed work interval, milliseconds since Unix epoch.',
      },
      {
        shortname: 'work-project',
        name: 'Project',
        datatype: Datatype.ATOMIC_URL,
        description: 'Project this work interval belongs to.',
      },
      {
        shortname: 'work-person',
        name: 'Person',
        datatype: Datatype.ATOMIC_URL,
        description: 'Person who performed this work.',
      },
      {
        shortname: 'work-billable',
        name: 'Billable',
        datatype: Datatype.BOOLEAN,
        description:
          'Whether this work interval is marked billable. Does not imply invoicing or payment.',
      },
      {
        shortname: 'work-source-id',
        name: 'Source identity',
        datatype: Datatype.STRING,
        description:
          'Provider-qualified record identity used to avoid duplicate imports. Not a display name.',
      },
    ],
    classes: [
      {
        shortname: 'work-project',
        name: 'Project',
        description: 'A named body of work.',
      },
      {
        shortname: 'work-person',
        name: 'Person',
        description:
          'A person participating in work. Not an Atomic authentication agent.',
      },
    ],
  };
}
