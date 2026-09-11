/** Explicit opt-in: creates a conversation and makes two no-tools model calls. */
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { connect } from './atomic.js';
import { core } from './model.mjs';
if (process.env.ATOMIC_CODEX_LIVE !== '1')
  throw new Error(
    'Set ATOMIC_CODEX_LIVE=1 to authorize two live no-tools model calls',
  );
const file = resolve(process.argv[2] || 'connection.json');
const c = JSON.parse(await readFile(file, 'utf8'));
const store = await connect(
  c.serverUrl,
  await readFile(file + '.secret', 'utf8'),
  c.drive,
  false,
);
const conversation = await store.newResource({
  parent: c.data,
  isA: [c.rowClass],
  propVals: {
    [core + 'name']: 'Codex live verification',
    [c.properties.created]: Date.now(),
  },
});
await conversation.save();
let thread;
for (const [prompt, expected] of [
  [
    'Remember the word ORCHARD. Reply with exactly ATOMIC_CODEX_OK. Do not use any tools.',
    'ATOMIC_CODEX_OK',
  ],
  [
    'What word did I ask you to remember? Reply with that word only. Do not use any tools.',
    'ORCHARD',
  ],
]) {
  const turn = await store.newResource({
    parent: conversation.subject,
    isA: [c.turnClass],
    propVals: {
      [c.properties.prompt]: prompt,
      [c.properties.state]: 'queued',
      [c.properties.created]: Date.now(),
    },
  });
  await turn.save();
  let completed = false;
  for (let i = 0; i < 120; i++) {
    await new Promise(resolve => setTimeout(resolve, 1000));
    await turn.refresh();
    const state = turn.get(c.properties.state);
    if (state === 'completed') {
      completed = true;
      break;
    }
    if (['failed', 'interrupted', 'uncertain'].includes(String(state)))
      throw new Error(`Turn ${state}: ${turn.get(c.properties.error)}`);
  }
  if (!completed)
    throw new Error('Timed out; check the worker before rerunning');
  const items = turn.get(c.properties.transcript) as any[];
  if (
    !items.some(x => x.type === 'agentMessage' && x.text?.trim() === expected)
  )
    throw new Error('Unexpected model response');
  await conversation.refresh();
  const current = conversation.get(c.properties.thread);
  if (thread && current !== thread)
    throw new Error('Continuation changed thread identity');
  thread = current;
}
console.log(
  'LIVE_OK: two persisted replies, same Codex thread, conversation context retained',
);
process.exit(0);
