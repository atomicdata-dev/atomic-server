import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startServer, type ServerHandle } from './server-fixture.js';
import { Store } from '../src/store.js';
import { Agent } from '../src/agent.js';
import { grantAgent } from '../src/agent-grants.js';
import { signRequest } from '../src/authentication.js';
import { server } from '../src/ontologies/server.js';
import { core } from '../src/ontologies/core.js';
import { Bridge } from '../../mcp/src/bridge.js';
import { connect as connectBridge } from '../../mcp/src/oauth.js';

/**
 * The hosted MCP endpoint against a live atomic-server: dynamic client
 * registration, approval by a signed-in person, PKCE code exchange, and then
 * the read-only tools as the issued agent. Real Store and fetch, no mocks.
 *
 * Spawns its own atomic-server (see `server-fixture.ts`).
 */
let SERVER = '';
const REDIRECT = 'http://localhost:7777/callback';
const b64url = (bytes: Buffer) => bytes.toString('base64url');

async function newDrive(store: Store, did: string, name: string) {
  const drive = await store.newResource({
    isA: server.classes.drive,
    noParent: true,
    propVals: {
      [core.properties.name]: name,
      [core.properties.write]: [did],
      [core.properties.read]: [did],
    },
  });
  await drive.save();

  return drive;
}

async function signedPost(store: Store, path: string, body: object) {
  const url = new URL(path, SERVER).href;
  const payload = JSON.stringify(body);
  const headers = await signRequest(
    url,
    store.getAgent()!,
    {},
    { method: 'POST', body: payload },
  );

  return fetch(url, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: payload,
  });
}

async function rpc(token: string, method: string, params?: object, id = 1) {
  const response = await fetch(`${SERVER}/mcp`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
  });

  return { response, json: (await response.json()) as any };
}

const tool = async (token: string, name: string, args: object) => {
  const { json } = await rpc(token, 'tools/call', { name, arguments: args });
  const text = json.result.content[0].text as string;

  return { text, isError: json.result.isError as boolean };
};

describe('hosted MCP against a live server', () => {
  let handle: ServerHandle;

  beforeAll(async () => {
    handle = await startServer();
    SERVER = handle.serverUrl;
  }, 120_000);

  /** Every store a test opened. Their sockets are closed before the server
   * goes: left open, the server's exit makes each one log "Server
   * disconnected" after the last test, when vitest is already closing the
   * worker, and a log that arrives then fails the run
   * (`EnvironmentTeardownError: Closing rpc while "onUserConsoleLog" was
   * pending`) with every test green. */
  const stores: Store[] = [];
  const openStore = (agent: Agent) => {
    const store = new Store({ serverUrl: SERVER, agent });
    stores.push(store);

    return store;
  };

  afterAll(async () => {
    for (const store of stores) {
      store.disconnect();
      // The outbox re-arms its retry timer only while the store counts itself
      // connected; a commit the server refused would otherwise keep retrying,
      // and logging, into the next teardown.
      store.setServerConnected(false);
    }

    // Let the close frames and whatever they log land while the file is live.
    await new Promise(resolve => setTimeout(resolve, 500));
    await handle?.stop();
  });

  it('approves a client and lets it read only what was shared', async () => {
    const agent = await Agent.fromSecret(handle.agentSecret);
    const did = agent.subject;
    const store = openStore(agent);
    store.setServerConnected(true);
    const shared = await newDrive(store, did, 'Shared with the client');
    const kept = await newDrive(store, did, 'Kept private');

    // Discovery and registration.
    const meta = await (
      await fetch(`${SERVER}/.well-known/oauth-authorization-server`)
    ).json();
    expect(meta.code_challenge_methods_supported).toEqual(['S256']);

    const registered = await fetch(meta.registration_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Test client',
        redirect_uris: [REDIRECT],
      }),
    });
    expect(registered.status).toBe(201);
    const { client_id: clientId } = (await registered.json()) as {
      client_id: string;
    };

    // Not a registered redirect: refused, never redirected to.
    const bad = await fetch(
      `${SERVER}/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: 'https://evil.example/cb',
        code_challenge: 'x',
        code_challenge_method: 'S256',
      })}`,
      { redirect: 'manual' },
    );
    expect(bad.status).toBe(400);

    // The browser is sent to the consent page in the app.
    const verifier = b64url(randomBytes(32));
    const challenge = b64url(createHash('sha256').update(verifier).digest());
    const authorize = await fetch(
      `${SERVER}/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: REDIRECT,
        code_challenge: challenge,
        code_challenge_method: 'S256',
        state: 'abc',
      })}`,
      { redirect: 'manual' },
    );
    expect(authorize.status).toBe(302);
    const consent = new URL(authorize.headers.get('location')!);
    expect(consent.pathname).toBe('/app/authorize-mcp');
    expect(consent.searchParams.get('client_name')).toBe('Test client');

    // Nobody signed in cannot approve.
    const anonymous = await fetch(`${SERVER}/oauth/agent`, {
      method: 'POST',
      body: JSON.stringify({ client_id: clientId }),
    });
    expect(anonymous.status).toBeGreaterThanOrEqual(400);

    // The person approves: an issued agent, rights on one drive, then the code.
    const issued = (await (
      await signedPost(store, '/oauth/agent', { client_id: clientId })
    ).json()) as { agent: string; nonce: string };
    await grantAgent(store, issued.agent, [shared.subject], false);

    const approved = await signedPost(store, '/oauth/approve', {
      client_id: clientId,
      redirect_uri: REDIRECT,
      code_challenge: challenge,
      nonce: issued.nonce,
      state: 'abc',
    });
    expect(approved.status).toBe(200);
    const back = new URL(
      ((await approved.json()) as { redirect_url: string }).redirect_url,
    );
    expect(back.origin + back.pathname).toBe(REDIRECT);
    expect(back.searchParams.get('state')).toBe('abc');
    const code = back.searchParams.get('code')!;

    // The person sees the client's name, not a key, under Connected apps.
    const named = await store.getResource(issued.agent);
    expect(named.get(core.properties.name)).toBe('Test client');

    const exchange = (body: Record<string, string>) =>
      fetch(`${SERVER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: clientId,
          redirect_uri: REDIRECT,
          code,
          ...body,
        }),
      });

    // PKCE binds the code to whoever started the flow.
    expect((await exchange({ code_verifier: 'wrong' })).status).toBe(400);
    const tokens = (await (
      await exchange({ code_verifier: verifier })
    ).json()) as { access_token: string; refresh_token: string };
    expect(tokens.access_token).toBeTruthy();
    // A code works once.
    expect((await exchange({ code_verifier: verifier })).status).toBe(400);

    // The endpoint: protocol basics.
    const anonymousMcp = await fetch(`${SERVER}/mcp`, {
      method: 'POST',
      body: '{}',
    });
    expect(anonymousMcp.status).toBe(401);
    expect(anonymousMcp.headers.get('www-authenticate')).toContain(
      'oauth-protected-resource',
    );

    const token = tokens.access_token;
    const init = await rpc(token, 'initialize', {
      protocolVersion: '2025-06-18',
    });
    expect(init.json.result.serverInfo.name).toBe('atomic');
    const list = await rpc(token, 'tools/list');
    expect(list.json.result.tools.map((t: any) => t.name)).toEqual([
      'list_drives',
      'get_resource',
      'search',
      'query',
      'find_schema',
      'get_user_classes',
      'get_schema',
    ]);

    // Read-only means read-only: the write tools are neither listed nor callable.
    const refused = await tool(tokens.access_token, 'create_resource', {
      resources: [{ '@class': 'folder', '@parent': shared.subject, name: 'x' }],
    });
    expect(refused.isError).toBe(true);
    expect(refused.text).toMatch(/read-only/);

    // Reads: what was shared, and nothing else.
    const drives = await tool(token, 'list_drives', {});
    expect(drives.text).toContain(shared.subject);
    expect(drives.text).not.toContain(kept.subject);

    const read = await tool(token, 'get_resource', {
      subjects: [shared.subject, kept.subject],
    });
    const parsed = JSON.parse(read.text);
    expect(parsed[shared.subject].name).toBe('Shared with the client');
    expect(String(parsed[kept.subject])).toMatch(/^Error:/);

    // A refresh token gives a working access token again.
    const refreshed = (await (
      await fetch(`${SERVER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: tokens.refresh_token,
        }),
      })
    ).json()) as { access_token: string };
    expect(
      (await tool(refreshed.access_token, 'list_drives', {})).text,
    ).toContain(shared.subject);

    // Revoking is taking the issued agent off the drive.
    await shared.set(core.properties.read, [did]);
    await shared.save();
    const after = await tool(token, 'get_resource', {
      subjects: [shared.subject],
    });
    expect(String(JSON.parse(after.text)[shared.subject])).toMatch(/^Error:/);

    // Tokens are not interchangeable: a refresh token is no access token.
    expect((await rpc(tokens.refresh_token, 'ping')).response.status).toBe(401);
  }, 60_000);

  /** Connects a client the way the consent page does, and returns its token. */
  async function connect(
    store: Store,
    name: string,
    drives: string[],
    write: boolean,
  ) {
    const registered = (await (
      await fetch(`${SERVER}/oauth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_name: name, redirect_uris: [REDIRECT] }),
      })
    ).json()) as { client_id: string };
    const verifier = b64url(randomBytes(32));
    const challenge = b64url(createHash('sha256').update(verifier).digest());
    const issued = (await (
      await signedPost(store, '/oauth/agent', {
        client_id: registered.client_id,
      })
    ).json()) as { agent: string; nonce: string };
    await grantAgent(store, issued.agent, drives, write);
    const approved = (await (
      await signedPost(store, '/oauth/approve', {
        client_id: registered.client_id,
        redirect_uri: REDIRECT,
        code_challenge: challenge,
        nonce: issued.nonce,
        write,
      })
    ).json()) as { redirect_url: string };
    const code = new URL(approved.redirect_url).searchParams.get('code')!;
    const token = (await (
      await fetch(`${SERVER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: registered.client_id,
          redirect_uri: REDIRECT,
          code,
          code_verifier: verifier,
        }),
      })
    ).json()) as { access_token: string; scope: string };

    return {
      token: token.access_token,
      scope: token.scope,
      agent: issued.agent,
    };
  }

  it('lets a client that may edit create, edit, query and delete', async () => {
    const agent = await Agent.fromSecret(handle.agentSecret);
    const store = openStore(agent);
    store.setServerConnected(true);
    const shared = await newDrive(store, agent.subject, 'Editable drive');
    const kept = await newDrive(store, agent.subject, 'Not shared');

    const {
      token,
      scope,
      agent: issued,
    } = await connect(store, 'Editing client', [shared.subject], true);
    expect(scope).toBe('read write');

    const list = await rpc(token, 'tools/list');
    const names = list.json.result.tools.map((t: any) => t.name);
    expect(names).toEqual(
      expect.arrayContaining([
        'edit_resource',
        'create_resource',
        'delete_resource',
        'ensure_ontology',
      ]),
    );

    // Create a folder and a document with Markdown text inside it.
    const folder = await tool(token, 'create_resource', {
      resources: [
        { '@class': 'folder', '@parent': shared.subject, name: 'Notes' },
      ],
    });
    expect(folder.isError).toBe(false);
    const folderSubject = JSON.parse(folder.text).created[0] as string;
    expect(folderSubject).not.toContain('placeholder');
    expect(folderSubject.length).toBeGreaterThan(40);

    const doc = await tool(token, 'create_resource', {
      resources: [
        {
          '@class': 'document',
          '@parent': folderSubject,
          name: 'Meeting notes',
          _documentText:
            '# Plan\n\n- [x] done\n- [ ] todo\n\nSome **bold** text',
        },
      ],
    });
    expect(doc.isError).toBe(false);
    const docSubject = JSON.parse(doc.text).created[0] as string;

    const read = JSON.parse(
      (await tool(token, 'get_resource', { subjects: [docSubject] })).text,
    )[docSubject];
    expect(read.name).toBe('Meeting notes');
    expect(read._documentText).toContain('Plan');
    expect(read._documentText).toContain('Some bold text');

    // The person sees the same through their own client, so it is a real commit
    // by the issued agent: the app's name is the author, not the person.
    const seen = await store.getResource(docSubject);
    expect(seen.get(core.properties.name)).toBe('Meeting notes');

    // Edits: a property and the text.
    const renamed = await tool(token, 'edit_resource', {
      subject: docSubject,
      property: 'name',
      value: 'Renamed notes',
    });
    expect(renamed.isError).toBe(false);
    const retexted = await tool(token, 'edit_resource', {
      subject: docSubject,
      property: '_documentText',
      value: 'Only this now',
    });
    expect(retexted.isError).toBe(false);
    const again = JSON.parse(
      (await tool(token, 'get_resource', { subjects: [docSubject] })).text,
    )[docSubject];
    expect(again.name).toBe('Renamed notes');
    expect(again._documentText).toBe('Only this now');

    // Querying children of the folder.
    const found = await tool(token, 'query', {
      where: [
        {
          property: 'https://atomicdata.dev/properties/parent',
          value: folderSubject,
        },
      ],
      parents: [shared.subject],
    });
    expect(found.text).toContain(docSubject);

    // Schemas: describe a type as JSON Schema, find it again, create a row of it.
    const shop = {
      title: 'Shop',
      $defs: {
        customer: {
          type: 'object',
          properties: {
            name: { type: 'string', minLength: 1 },
            tier: { type: 'string', enum: ['free', 'pro'] },
          },
          required: ['name'],
        },
      },
    };
    const ensured = await tool(token, 'ensure_ontology', {
      drive: shared.subject,
      schema: shop,
    });
    expect(ensured.isError).toBe(false);
    const made = JSON.parse(ensured.text);
    expect(made.shortname).toBe('shop');
    expect(made.classes.customer).toBeTruthy();

    // Idempotent.
    const repeated = await tool(token, 'ensure_ontology', {
      drive: shared.subject,
      schema: shop,
    });
    expect(JSON.parse(repeated.text)).toEqual(made);

    // An invalid schema names the JSON pointer.
    const invalid = await tool(token, 'ensure_ontology', {
      drive: shared.subject,
      schema: {
        title: 'Bad',
        $defs: { x: { type: 'object', properties: { y: { oneOf: [] } } } },
      },
    });
    expect(invalid.isError).toBe(true);
    expect(invalid.text).toContain('/$defs/x/properties/y');

    const foundSchema = JSON.parse(
      (await tool(token, 'find_schema', { query: 'customer' })).text,
    );
    expect(foundSchema.matches[0].class).toBe(made.classes.customer);
    expect(foundSchema.matches[0].jsonSchema.required).toEqual(['name']);
    expect(foundSchema.matches[0].jsonSchema.properties.tier.enum).toEqual([
      'free',
      'pro',
    ]);

    // The deprecated listing still answers, in the old shape plus the schema.
    const legacy = JSON.parse(
      (await tool(token, 'get_user_classes', { drive: shared.subject })).text,
    );
    expect(legacy.map((c: any) => c.subject)).toContain(made.classes.customer);

    const row = await tool(token, 'create_resource', {
      resources: [
        {
          '@class': made.classes.customer,
          '@parent': shared.subject,
          name: 'Anna',
          tier: 'pro',
        },
      ],
    });
    expect(row.isError).toBe(false);

    // Nobody else can put an ontology on a drive that was not shared.
    const elsewhere = await tool(token, 'ensure_ontology', {
      drive: kept.subject,
      schema: shop,
    });
    expect(elsewhere.isError).toBe(true);

    // What was not shared cannot be written, even with edit rights elsewhere.
    const outside = await tool(token, 'create_resource', {
      resources: [{ '@class': 'folder', '@parent': kept.subject, name: 'No' }],
    });
    expect(outside.isError).toBe(true);
    const outsideEdit = await tool(token, 'edit_resource', {
      subject: kept.subject,
      property: 'name',
      value: 'Hijacked',
    });
    expect(outsideEdit.isError).toBe(true);

    // A drive cannot be deleted from here; a folder can, with what is in it.
    expect(
      (await tool(token, 'delete_resource', { subject: shared.subject }))
        .isError,
    ).toBe(true);
    const deleted = await tool(token, 'delete_resource', {
      subject: folderSubject,
    });
    expect(deleted.isError).toBe(false);
    const gone = JSON.parse(
      (await tool(token, 'get_resource', { subjects: [docSubject] })).text,
    )[docSubject];
    expect(String(gone)).toMatch(/^Error:/);

    // Revoking: the agent loses its rights and its writes stop.
    await shared.set(core.properties.read, [agent.subject]);
    await shared.set(core.properties.write, [agent.subject]);
    await shared.save();
    const after = await tool(token, 'create_resource', {
      resources: [
        { '@class': 'folder', '@parent': shared.subject, name: 'Late' },
      ],
    });
    expect(after.isError).toBe(true);
    expect(issued).toContain(':agent:');
  }, 90_000);

  it('serves the local bridge through the same endpoint, after the same approval', async () => {
    process.env.XDG_CONFIG_HOME = await mkdtemp(path.join(tmpdir(), 'bridge-'));
    const agent = await Agent.fromSecret(handle.agentSecret);
    const store = openStore(agent);
    store.setServerConnected(true);
    const shared = await newDrive(store, agent.subject, 'Bridge drive');

    // The person's side: what the consent page does after the browser lands there.
    const approve = async (link: string) => {
      const consent = new URL(
        (await fetch(link, { redirect: 'manual' })).headers.get('location')!,
      );
      const query = consent.searchParams;
      expect(query.get('scope')).toBe('read write');
      const issued = (await (
        await signedPost(store, '/oauth/agent', {
          client_id: query.get('client_id'),
        })
      ).json()) as { agent: string; nonce: string };
      await grantAgent(store, issued.agent, [shared.subject], true);
      const approved = (await (
        await signedPost(store, '/oauth/approve', {
          client_id: query.get('client_id'),
          redirect_uri: query.get('redirect_uri'),
          code_challenge: query.get('code_challenge'),
          nonce: issued.nonce,
          write: true,
          state: query.get('state'),
        })
      ).json()) as { redirect_url: string };
      await fetch(approved.redirect_url);
    };

    const connection = await connectBridge({
      server: SERVER,
      clientName: 'Bridge test',
      write: true,
      openUrl: link => void approve(link),
    });
    expect(connection.scope).toBe('read write');

    const bridge = new Bridge(SERVER);
    const call = async (name: string, args: object) => {
      const answer = (await bridge.handle({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name, arguments: args },
      })) as any;

      return answer.result.content[0].text as string;
    };

    const created = JSON.parse(
      await call('create_resource', {
        resources: [
          {
            '@class': 'document',
            '@parent': shared.subject,
            name: 'Via bridge',
            _documentText: 'Hello',
          },
        ],
      }),
    );
    const read = JSON.parse(
      await call('get_resource', { subjects: [created.created[0]] }),
    );
    expect(read[created.created[0]]._documentText).toBe('Hello');
  }, 90_000);
});
