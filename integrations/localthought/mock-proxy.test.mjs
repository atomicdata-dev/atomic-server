import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { mockProxy, tenantSecret } from './mock-proxy.mjs';
test('catalog, signed handoff, provider read and single-use rotation', async () => {
  const server = mockProxy();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    assert.deepEqual(await (await fetch(`${base}/catalog`)).json(), ['github-issues', 'google-calendar', 'pets']);
    const challenge = await (await fetch(`${base}/session`)).json();
    const sign = value => createHmac('sha256', tenantSecret).update(value).digest('base64url');
    const url = new URL(`${base}/connect`);
    url.search = new URLSearchParams({ ...challenge, redirect_uri: 'http://localhost:6747/app/integrations?integration_state=abc', platform: 'pets', tenant_id: 'mock-tenant', user_id: 'agent', user_id_sig: sign('agent'), response: sign(challenge.challenge) });
    const bad = new URL(url); bad.searchParams.set('response', 'invalid');
    assert.equal((await fetch(bad)).status, 401);
    const consent = await fetch(url, { method: 'POST', redirect: 'manual' });
    assert.equal(consent.status, 303);
    const code = new URL(consent.headers.get('location')).searchParams.get('connection_code');
    const read = (token, query = '') => fetch(`${base}/proxy/pets/pets${query}`, { headers: { Authorization: `Bearer ${token}` } });
    const first = await read(code);
    assert.equal((await first.json()).length, 2);
    assert.match(first.headers.get('link'), /page=2/);
    assert.equal((await read(code)).status, 401);
    const second = await read(first.headers.get('x-connection-code'), '?page=2');
    assert.equal((await second.json()).length, 3);
    assert.equal((await fetch(url, { method: 'POST' })).status, 401);
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});
