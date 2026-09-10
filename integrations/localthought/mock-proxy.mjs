/** Local-only integration-proxy fixture. Never deploy this service. */
import { calendarDocument, calendarFixture } from './mock-calendar.mjs';
import { githubTracker } from './mock-github.mjs';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { pathToFileURL } from 'node:url';
const equal = (a, b) =>
  typeof a === 'string' &&
  typeof b === 'string' &&
  a.length === b.length &&
  timingSafeEqual(Buffer.from(a), Buffer.from(b));
const pkceChallenge = verifier =>
  createHash('sha256').update(verifier).digest('base64url');
const platforms = {
  'github-issues': 'GitHub Issues',
  'google-calendar': 'Google Calendar',
  pets: 'Pets',
};
const pets = ['Rex', 'Whiskers', 'Tweety', 'Nibbles', 'Bubbles'].map(
  (name, i) => ({
    id: i + 1,
    name,
    species: ['Dog', 'Cat', 'Bird', 'Rabbit', 'Fish'][i],
    age: i + 1,
    vaccinated: i % 2 === 0,
    weight: i + 0.5,
    updated_at: '2026-09-09T00:00:00Z',
  }),
);
export function mockProxy({
  frontendOrigin = process.env.MOCK_FRONTEND_ORIGIN ?? 'http://localhost:6747',
} = {}) {
  const github = githubTracker();
  const calendar = calendarFixture();
  const codes = new Map();
  const handoffs = new Map();
  const issueCode = platform => {
    const code = randomBytes(32).toString('base64url');
    codes.set(code, platform);
    return code;
  };
  const server = createServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader(
      'Access-Control-Allow-Methods',
      'GET, POST, PATCH, DELETE, OPTIONS',
    );
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Authorization, Content-Type',
    );
    res.setHeader('Access-Control-Expose-Headers', 'X-Connection-Code, Link');
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      return res.end();
    }

    const url = new URL(req.url, 'http://localhost');
    const json = (status, value, headers = {}) => {
      res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
      res.end(JSON.stringify(value));
    };
    if (url.pathname === '/catalog')
      return json(200, ['github-issues', 'google-calendar', 'pets']);
    if (url.pathname === '/catalog/pets.yaml') {
      res.writeHead(200, { 'Content-Type': 'application/yaml' });
      return res.end(
        readFileSync(new URL('./mock-document.json', import.meta.url)),
      );
    }
    if (url.pathname === '/catalog/google-calendar.yaml')
      return json(200, calendarDocument);
    if (url.pathname === '/connect') {
      const p = url.searchParams;
      const platform = p.get('platform');
      const verifierChallenge = p.get('code_challenge');
      if (
        !Object.hasOwn(platforms, platform) ||
        !verifierChallenge ||
        p.get('code_challenge_method') !== 'S256' ||
        p.get('credentials') !== 'connection' ||
        !p.get('user_id')
      )
        return json(400, { error: 'Invalid connection request' });
      let redirect;
      try {
        redirect = new URL(p.get('redirect_uri'));
      } catch {
        return json(400, { error: 'Invalid callback' });
      }
      if (
        redirect.origin !== frontendOrigin ||
        !['/app/integrations', '/app/devonian-demo'].includes(redirect.pathname) ||
        !redirect.searchParams.get('integration_state') ||
        redirect.searchParams.get('platform') !== platform
      )
        return json(400, { error: 'Invalid callback' });
      if (req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end(
          `<h1>Mock integration proxy</h1><p>Signed in as mock-user.</p><p>Use the selected ${platforms[platform]} account to sync with your Atomic Data Hub.</p><form method="post"><button>Use LocalThought to sync ${platforms[platform]} with your Atomic Data Hub</button></form>`,
        );
      }
      if (req.method !== 'POST') return json(405, {});
      const handoff = randomBytes(32).toString('base64url');
      handoffs.set(handoff, {
        platform,
        userId: p.get('user_id'),
        codeChallenge: verifierChallenge,
      });
      redirect.searchParams.set('connection_code', handoff);
      res.writeHead(303, { Location: redirect.href });
      return res.end();
    }
    if (url.pathname === '/connect/redeem') {
      if (req.method !== 'POST') return json(405, {});
      let body;
      try {
        let text = '';
        for await (const chunk of req) {
          text += chunk;
          if (text.length > 16 * 1024) return json(413, {});
        }
        body = JSON.parse(text);
      } catch {
        return json(400, { error: 'Invalid redemption body' });
      }
      const handoff = handoffs.get(body?.code);
      if (
        !handoff ||
        typeof body?.code_verifier !== 'string' ||
        !equal(pkceChallenge(body.code_verifier), handoff.codeChallenge)
      )
        return json(400, { error: 'Invalid or consumed connection code' });
      handoffs.delete(body.code);
      return json(200, {
        connection_code: issueCode(handoff.platform),
        platform: handoff.platform,
      });
    }
    if (url.pathname.startsWith('/proxy/')) {
      const code = req.headers.authorization?.replace(/^Bearer /, '');
      const platform = codes.get(code);
      if (!platform)
        return json(401, { error: 'Invalid or consumed connection code' });
      codes.delete(code);
      const headers = { 'X-Connection-Code': issueCode(platform) };
      if (!url.pathname.startsWith(`/proxy/${platform}/`))
        return json(403, {}, headers);
      if (platform === 'github-issues') {
        try {
          let body = '';
          for await (const chunk of req) {
            body += chunk;
            if (body.length > 1024 * 1024) return json(413, {}, headers);
          }
          const result = github.request(
            req.method,
            url,
            body ? JSON.parse(body) : {},
          );
          return json(result.status, result.body, headers);
        } catch {
          return json(400, { error: 'Invalid request body' }, headers);
        }
      }
      if (platform === 'google-calendar') {
        const result = calendar.request(req.method, url);
        return json(result.status, result.body, headers);
      }
      if (req.method !== 'GET') return json(403, {}, headers);
      const data =
        platform === 'pets'
          ? url.searchParams.get('page') === '2'
            ? pets.slice(2)
            : pets.slice(0, 2)
          : { items: [{ id: 'event-1', summary: 'Team meeting' }] };
      return json(200, data, {
        ...headers,
        ...(platform === 'pets' && !url.searchParams.has('page')
          ? { Link: '<https://pets.example/pets?page=2>; rel="next"' }
          : {}),
      });
    }
    json(404, {});
  });
  server.github = github;
  server.calendar = calendar;
  return server;
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  mockProxy().listen(
    Number(process.env.MOCK_PROXY_PORT ?? 19090),
    process.env.MOCK_PROXY_HOST ?? '127.0.0.1',
    () =>
      console.log('Mock integration proxy listening on http://127.0.0.1:19090'),
  );
}
