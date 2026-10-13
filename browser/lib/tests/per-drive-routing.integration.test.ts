import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { startServer, type ServerHandle } from './server-fixture.js';
import { Store } from '../src/store.js';
import { Agent } from '../src/agent.js';
import { core } from '../src/ontologies/core.js';
import { server } from '../src/ontologies/server.js';
import { signRequest } from '../src/authentication.js';
import { CollectionBuilder } from '../src/collectionBuilder.js';

/** Separate real nodes: a shared database cannot hide a misrouted write. */
describe('per-drive routing across live nodes and subdomains', () => {
  let a: ServerHandle;
  let b: ServerHandle;
  const stores: Store[] = [];
  beforeAll(async () => {
    [a, b] = await Promise.all([startServer(), startServer({ servedDomainSuffix: 'routing.test' })]);
  }, 120_000);
  afterAll(async () => {
    for (const store of stores) store.disconnect();
    await Promise.all([a?.stop(), b?.stop()]);
  });

  it('saves, reads, queries and keeps live subscriptions on two nodes while switching drives', async () => {
    const agent = await Agent.fromSecret(a.agentSecret);
    const owner = new Store({ serverUrl: a.serverUrl, agent });
    stores.push(owner);
    expect(await owner.waitForServerConnected(10_000)).toBe(true);
    const makeDrive = async (name: string, origin: string) => {
      const drive = await owner.newResource({ isA: server.classes.drive, noParent: true,
        propVals: { [core.properties.name]: name, [core.properties.read]: [agent.subject!], [core.properties.write]: [agent.subject!] } });
      owner.setDriveServer(drive.subject, origin);
      expect(await owner.waitForServerConnected(10_000, drive.subject)).toBe(true);
      await drive.save();
      return drive;
    };
    const da = await makeDrive('Node A', a.serverUrl);
    const db = await makeDrive('Node B', b.serverUrl);
    const ca = await owner.newResource({ parent: da.subject, propVals: { [core.properties.name]: 'A before' } });
    const cb = await owner.newResource({ parent: db.subject, propVals: { [core.properties.name]: 'B before' } });
    await ca.save(); await cb.save();
    const reader = new Store({ serverUrl: b.serverUrl, agent });
    stores.push(reader);
    reader.setDriveServer(da.subject, a.serverUrl);
    reader.setDriveServer(db.subject, b.serverUrl);
    reader.setDrive(db.subject);
    await reader.waitForServerConnected(10_000, da.subject);
    await reader.waitForServerConnected(10_000, db.subject);
    await reader.fetchResourceFromServer(da.subject);
    await reader.fetchResourceFromServer(db.subject);
    const releaseA = reader.subscribeLive(da.subject);
    const releaseB = reader.subscribeLive(db.subject);
    const coldQuery = await new CollectionBuilder(reader).setProperty(core.properties.parent).setValue(da.subject).buildAndFetch();
    expect(await coldQuery.getAllMembers()).toContain(ca.subject);
    const ra = await reader.fetchResourceFromServer(ca.subject);
    const rb = await reader.fetchResourceFromServer(cb.subject, { drive: db.subject });
    owner.setServerUrl(b.serverUrl);
    owner.setDrive(db.subject);
    await ca.set(core.properties.name, 'A after switching', false); await ca.save();
    await cb.set(core.properties.name, 'B after switching', false); await cb.save();
    await vi.waitFor(() => expect(ra.get(core.properties.name)).toBe('A after switching'), { timeout: 10_000 });
    await vi.waitFor(() => expect(rb.get(core.properties.name)).toBe('B after switching'), { timeout: 10_000 });
    const query = await new CollectionBuilder(reader).setProperty(core.properties.parent).setValue(da.subject).buildAndFetch();
    expect(await query.getAllMembers()).toContain(ca.subject);
    owner.getWebSocketForSubject(da.subject)!.close();
    await cb.set(core.properties.name, 'B while A is offline', false); await cb.save();
    await vi.waitFor(() => expect(rb.get(core.properties.name)).toBe('B while A is offline'), { timeout: 10_000 });
    await owner.reconnect(10_000, da.subject);
    await ca.set(core.properties.name, 'A reconnected', false); await ca.save();
    await vi.waitFor(() => expect(ra.get(core.properties.name)).toBe('A reconnected'), { timeout: 10_000 });
    const wrongNode = `${b.serverUrl}/resource?subject=${encodeURIComponent(ca.subject)}`;
    const wrong = await fetch(wrongNode, { headers: await signRequest(wrongNode, agent, { Accept: 'application/ad+json' }) });
    expect([401, 404]).toContain(wrong.status);
    releaseA(); releaseB();
  });

  it('keeps an anonymous live subscription receiving pushes after first login', async () => {
    const agent = await Agent.fromSecret(a.agentSecret);
    const owner = new Store({ serverUrl: a.serverUrl, agent });
    stores.push(owner);
    await owner.waitForServerConnected(10_000);
    const drive = await owner.newResource({ isA: server.classes.drive, noParent: true, propVals: {
      [core.properties.name]: 'Public before login',
      [core.properties.read]: ['https://atomicdata.dev/agents/publicAgent'],
      [core.properties.write]: [agent.subject!],
    } });
    await drive.save();
    const reader = new Store({ serverUrl: a.serverUrl });
    stores.push(reader);
    await reader.waitForServerConnected(10_000);
    const copy = await reader.fetchResourceFromServer(drive.subject);
    expect(copy.error).toBeUndefined();
    const release = reader.subscribeLive(drive.subject);
    reader.setAgent(await Agent.fromSecret(b.agentSecret));
    await reader.waitForServerConnected(10_000);
    await drive.set(core.properties.name, 'Public after login', false);
    await drive.save();
    await vi.waitFor(() => expect(copy.get(core.properties.name)).toBe('Public after login'), { timeout: 10_000 });
    release();
  });

  it('resolves and signs requests on the exact bound subdomain, preserving DID identity', async () => {
    const agent = await Agent.fromSecret(b.agentSecret);
    const owner = new Store({ serverUrl: b.serverUrl, agent });
    stores.push(owner);
    await owner.waitForServerConnected(10_000);
    const drive = await owner.newResource({ isA: server.classes.drive, noParent: true,
      propVals: { [core.properties.name]: 'Vanity tenant', [core.properties.read]: [agent.subject!], [core.properties.write]: [agent.subject!] } });
    await drive.save();
    const tenant = `http://alpha.routing.test:${new URL(b.serverUrl).port}`;
    const binding = `${tenant}/bind-drive`;
    const headers = await signRequest(binding, agent, { 'Content-Type': 'application/json', Accept: 'application/ad+json' });
    const bound = await fetch(`${b.serverUrl}/bind-drive`, { method: 'POST', headers: { ...headers, Host: new URL(tenant).host, 'X-Forwarded-Host': new URL(tenant).host },
      body: JSON.stringify({ ['https://atomicdata.dev/properties/initialDrive']: drive.subject }) });
    expect(bound.status, await bound.text()).toBe(200);
    // Only DNS is replaced: the server sees the tenant Host and verifies the
    // actual signature against that origin, rather than localhost.
    // A second browser has its own route preferences. A previously saved
    // explicit placement must not be silently migrated by an alias read.
    localStorage.removeItem(`atomic.driveServers.${agent.subject}`);
    const reader = new Store({ serverUrl: tenant, agent, connect: false });
    stores.push(reader);
    reader.injectFetch(async (input, init) => {
      const url = new URL(String(input));
      const headers = new Headers(init?.headers);
      headers.set('Host', url.host);
      headers.set('X-Forwarded-Host', url.host);
      return fetch(new URL(url.pathname + url.search, b.serverUrl), { ...init, headers });
    });
    const root = await reader.fetchResourceFromServer(`${tenant}/`, { noWebSocket: true });
    expect(root.error).toBeUndefined();
    expect(root.subject).toBe(drive.subject);
    expect(reader.getServerUrlForSubject(root.subject)).toBe(tenant);
    reader.setServerUrl(a.serverUrl, { connect: false });
    const refetched = await reader.fetchResourceFromServer(root.subject, { noWebSocket: true });
    expect(refetched.error).toBeUndefined();
    expect(refetched.get(core.properties.name)).toBe('Vanity tenant');
  });
});
