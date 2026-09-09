// @wc-ignore-file
/** Code-first automation starter. Event wiring is data; behavior is normal JS. */
export interface IntegrationEvent {
  id: string;
  name: string;
  description: string;
  filters: Array<{ property: string; value?: string }>;
}
export function eventAutomationSource(event: IntegrationEvent): string {
  return `export const manifest = { schemaVersion: 1, secrets: [], operations: [] };

// ${JSON.stringify(event.name)}
// The server queues matching events, including while this script awaits review.
// Reads cannot write. Return intents; the host reviews/applies and journals them.
export function run(ctx) {
  const filters = ${JSON.stringify(event.filters)};
  // Manual Run uses a matching record as a sample. Automatic runs carry the
  // actual event subject. Never invent sample data for an approval.
  const first = filters.find(f => f.value !== undefined);
  const subject = ctx.trigger.subject || (first ? ctx.query(first.property, first.value).find(subject => {
    const row = ctx.read(subject);
    return filters.every(f => f.value === undefined ? row[f.property] !== undefined : Array.isArray(row[f.property]) ? row[f.property].includes(f.value) : row[f.property] === f.value);
  }) : undefined);
  if (!subject) return { intents: [], problems: [{ severity: 'error', message: 'No matching event record yet. Create one, then run a sample.' }] };
  // trigger.id is stable across retries; trigger.at is the event timestamp.
  // read() returns the current authorized resource, not a historical snapshot.
  const record = ctx.read(subject);
  const intents = [];

  // Add conditions with ordinary JavaScript, and return any number of actions.
  // For example, uncomment this and replace the chatroom subject to post a message:
  // intents.push({ op: 'create', localId: 'message', parent: 'YOUR_CHATROOM_SUBJECT',
  //   isA: ['https://atomicdata.dev/classes/Message'], set: {
  //     'https://atomicdata.dev/properties/description': record['https://atomicdata.dev/properties/name'] || 'New record',
  //     'https://atomicdata.dev/properties/about': subject,
  //   } });
  // Other intents: { op: 'set', subject, set: { PROPERTY: VALUE } },
  // { op: 'remove', subject, properties: [PROPERTY] }, { op: 'destroy', subject }.
  // Creates can reference earlier creates using 'local:theirLocalId'.
  // Changes to connected Atomic records are sent by their integration's sync.
  return { intents, problems: [] };
}
`;
}
