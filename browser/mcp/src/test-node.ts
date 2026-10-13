import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

/** A pretend node: just enough of `/oauth` and `/mcp` to run the bridge against. */
export interface FakeNode {
  origin: string;
  requests: { path: string; auth?: string; body: string }[];
  /** Access tokens currently accepted. */
  valid: Set<string>;
  /** Called with the authorize URL in place of a browser; returns the callback URL. */
  approve: (authorizeUrl: string) => string;
  close: () => Promise<void>;
}

const readBody = (req: IncomingMessage) =>
  new Promise<string>(resolve => {
    let data = '';
    req.on('data', chunk => (data += chunk));
    req.on('end', () => resolve(data));
  });

export async function startFakeNode(): Promise<FakeNode> {
  const requests: FakeNode['requests'] = [];
  const valid = new Set<string>();
  let counter = 0;
  const codes = new Map<string, { redirect: string; challenge: string }>();
  let server!: Server;
  let origin = '';

  server = createServer(async (req, res) => {
    const body = await readBody(req);
    requests.push({
      path: req.url ?? '',
      auth: req.headers.authorization,
      body,
    });

    const json = (status: number, value: unknown) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(value));
    };

    if (req.url === '/.well-known/oauth-authorization-server') {
      return json(200, {
        authorization_endpoint: `${origin}/oauth/authorize`,
        registration_endpoint: `${origin}/oauth/register`,
      });
    }

    if (req.url === '/oauth/register') {
      return json(201, { client_id: 'client-1' });
    }

    if (req.url === '/oauth/token') {
      const form = new URLSearchParams(body);

      if (form.get('grant_type') === 'refresh_token') {
        if (form.get('refresh_token') !== 'refresh-1') {
          return json(400, { error: 'invalid_grant' });
        }

        const token = `access-${++counter}`;
        valid.clear();
        valid.add(token);

        return json(200, {
          access_token: token,
          expires_in: 3600,
          scope: 'read write',
        });
      }

      const issued = codes.get(form.get('code') ?? '');

      if (!issued || form.get('redirect_uri') !== issued.redirect) {
        return json(400, { error: 'invalid_grant' });
      }

      const token = `access-${++counter}`;
      valid.add(token);

      return json(200, {
        access_token: token,
        refresh_token: 'refresh-1',
        expires_in: 3600,
        scope: 'read write',
      });
    }

    if (req.url === '/mcp') {
      const token = req.headers.authorization?.replace('Bearer ', '') ?? '';

      if (!valid.has(token)) {
        res.writeHead(401).end();

        return;
      }

      const message = JSON.parse(body);

      if (message.id === undefined) {
        res.writeHead(202).end();

        return;
      }

      return json(200, {
        jsonrpc: '2.0',
        id: message.id,
        result: { echoed: message.method },
      });
    }

    res.writeHead(404).end();
  });

  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  return {
    origin,
    requests,
    valid,
    approve: authorizeUrl => {
      const url = new URL(authorizeUrl);
      const code = `code-${codes.size + 1}`;
      codes.set(code, {
        redirect: url.searchParams.get('redirect_uri')!,
        challenge: url.searchParams.get('code_challenge')!,
      });
      const back = new URL(url.searchParams.get('redirect_uri')!);
      back.searchParams.set('code', code);
      back.searchParams.set('state', url.searchParams.get('state')!);
      back.searchParams.set('iss', origin);

      return back.href;
    },
    close: () => new Promise(resolve => server.close(() => resolve())),
  };
}
