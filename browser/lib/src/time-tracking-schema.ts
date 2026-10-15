import { Datatype } from './datatypes.js';
import type { SchemaSpec } from './plugin-schema.js';

/**
 * Per-drive time tracking schema.
 *
 * @deprecated The Time tracker template binds to the shared `workSchema`
 * vocabulary instead, so its property IDs no longer depend on the drive. This
 * stays for callers (such as importers) that still allocate these properties in
 * a drive's own ontology; tables created that way are not migrated.
 */
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
