/** Shared browser/CLI installation; no filesystem or process access. */
import {
  type Store,
  signRequest,
  createApp,
  updateApp,
  ensureSchema,
} from '../../browser/lib/src/index.js';
import { fields } from './model.mjs';
export async function installApp(store: Store, drive: string, source: string) {
  const app = await createApp(store, {
    drive,
    name: 'Codex',
    emoji: '✳️',
    source,
    description: 'Conversations with your local Codex worker.',
    rowName: { singular: 'Conversation', plural: 'Conversations' },
  });
  const schema = await ensureSchema(store, app.app, {
    properties: Object.entries(fields).map(([key, datatype]) => ({
      shortname: `codex-${key}`,
      name: key,
      description: `Codex chat ${key}.`,
      datatype: `https://atomicdata.dev/datatypes/${datatype}` as any,
    })),
    classes: [
      {
        shortname: 'codex-turn',
        name: 'Turn',
        description: 'One requested Codex turn.',
      },
      {
        shortname: 'codex-approval',
        name: 'Approval',
        description: 'A pending Codex approval.',
      },
    ],
  });
  const properties = Object.fromEntries(
    Object.keys(fields).map(key => [key, schema.properties[`codex-${key}`]]),
  );
  const config = {
    version: 1,
    serverUrl: store.getServerUrl(),
    drive,
    app: app.app,
    data: app.data,
    entrypoint: app.entrypoint,
    rowClass: app.rowClass,
    turnClass: schema.classes['codex-turn'],
    approvalClass: schema.classes['codex-approval'],
    properties,
  };
  // Only vocabulary and resource bindings are embedded in the view.
  await updateApp(store, drive, {
    app: app.app,
    source: `const CONFIG = ${JSON.stringify(config)};\n${source}`,
  });
  const url = `${store.getServerUrl()}/app-agent`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      ...(await signRequest(url, store.getAgent()!, {})),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ drive, app: app.app, secret: app.secret }),
  });
  if (!response.ok)
    throw new Error(`App identity registration failed (${response.status})`);
  return { config, secret: app.secret };
}
