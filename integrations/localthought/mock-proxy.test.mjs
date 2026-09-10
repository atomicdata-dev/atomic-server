import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mockProxy } from './mock-proxy.mjs';

const verifier = 'a'.repeat(64);
const challenge = createHash('sha256').update(verifier).digest('base64url');

test('catalog, selected-platform PKCE consent, redemption and single-use rotation', async () => {
  const server = mockProxy();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    assert.deepEqual(
      await (await fetch(`${base}/catalog`)).json(),
      ['github-issues', 'google-calendar', 'pets'],
    );
    const callback =
      'http://localhost:6747/app/integrations?integration_state=abc&platform=pets';
    const url = new URL(`${base}/connect`);
    url.search = new URLSearchParams({
      redirect_uri: callback,
      platform: 'pets',
      user_id: 'synthetic-agent',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      credentials: 'connection',
    });
    const login = await fetch(url);
    assert.equal(login.status, 200);
    const loginHtml = await login.text();
    assert.match(
      loginHtml,
      /Use LocalThought to sync Pets with your Atomic Data Hub/,
    );
    assert.doesNotMatch(loginHtml, /tenant secret/i);
    assert.doesNotMatch(loginHtml, /GitHub|Google Calendar/);

    const badPlatform = new URL(url);
    badPlatform.searchParams.set('platform', 'github-issues');
    assert.equal((await fetch(badPlatform)).status, 400);

    const consent = await fetch(url, { method: 'POST', redirect: 'manual' });
    assert.equal(consent.status, 303);
    const location = new URL(consent.headers.get('location'));
    const handoff = location.searchParams.get('connection_code');
    assert.equal(location.searchParams.get('platform'), 'pets');
    assert.ok(handoff);

    const redeem = codeVerifier =>
      fetch(`${base}/connect/redeem`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: handoff, code_verifier: codeVerifier }),
      });
    assert.equal((await redeem('wrong-verifier')).status, 400);
    const redeemed = await redeem(verifier);
    assert.equal(redeemed.status, 200);
    const result = await redeemed.json();
    assert.equal(result.platform, 'pets');
    assert.equal(typeof result.connection_code, 'string');
    assert.ok(result.connection_code);
    assert.equal((await redeem(verifier)).status, 400);

    const read = (token, query = '') =>
      fetch(`${base}/proxy/pets/pets${query}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
    const first = await read(result.connection_code);
    assert.equal((await first.json()).length, 2);
    assert.match(first.headers.get('link'), /page=2/);
    assert.equal((await read(result.connection_code)).status, 401);
    const second = await read(first.headers.get('x-connection-code'), '?page=2');
    assert.equal((await second.json()).length, 3);
    assert.equal(
      (
        await fetch(`${base}/proxy/google-calendar/events`, {
          headers: {
            Authorization: `Bearer ${second.headers.get('x-connection-code')}`,
          },
        })
      ).status,
      403,
    );
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});
