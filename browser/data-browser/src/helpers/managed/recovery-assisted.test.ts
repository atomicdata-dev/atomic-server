// @wc-ignore-file
import { beforeEach, expect, it, vi } from 'vitest';
import {
  buildEnvelopeWithAssisted,
  decryptEnvelopeWithAssisted,
  FreshSignInRequiredError,
  hasAssistedWrapper,
  type RecoverySecret,
} from './recovery';
import { getManagedAccount } from './session';
import { managedFetch, getManagedApiBase } from './api';

vi.mock('./session', () => ({ getManagedAccount: vi.fn() }));
vi.mock('./api', () => ({
  managedFetch: vi.fn(),
  getManagedApiBase: vi.fn(),
  hasManagedApi: vi.fn(() => true),
}));
// The recovery code's Argon2id runs in WASM; the fixture stands in for it.
vi.mock('../wasmUrls', () => ({
  wasmJsUrl: () => './test-fixtures/recovery-wasm.ts',
  wasmBinaryUrl: () => '',
  atomicWasmSource: async () => '',
}));

const AGENT = 'atomic:agent:9Hc-J_2n4jIpXqzTZMDSnNFOFB1fWqCsGSk3Wdyy9Bs';

/** A stand-in for the account service: a key per (agent, salt), like the real
 * HMAC, and a switch for a sign-in that is too old to unlock with. */
function fakeService({ fresh }: { fresh: boolean }) {
  const keys = new Map<string, string>();
  const keyIds = new Map<string, string>();
  const seenSalts: string[] = [];
  const service = { currentKey: 'key-1', appended: [] as unknown[] };

  vi.mocked(managedFetch).mockImplementation(async (path, init) => {
    if (path === '/auth/providers') {
      return Response.json({ google: true, assisted_recovery: true });
    }

    if (path === '/recovery-secret/assisted-key') {
      const { agent_subject, salt } = JSON.parse(String(init?.body));
      const unlocking = seenSalts.includes(salt);

      if (unlocking && !fresh) {
        return Response.json(
          { error: 'Sign in again', error_code: 'fresh_sign_in_required' },
          { status: 403 },
        );
      }

      seenSalts.push(salt);
      const id = `${agent_subject}|${salt}`;

      if (!keys.has(id)) {
        const bytes = crypto.getRandomValues(new Uint8Array(32));
        keys.set(id, btoa(String.fromCharCode(...bytes)));
        keyIds.set(id, service.currentKey);
      }

      return Response.json({
        key: keys.get(id),
        key_id: keyIds.get(id),
        rotate: keyIds.get(id) !== service.currentKey,
      });
    }

    if (path === '/recovery-secret/wrappers') {
      const body = JSON.parse(String(init?.body));
      service.appended.push(body.wrapper);

      return Response.json({ ...body, owner_email: 'person@example.com' });
    }

    return new Response(null, { status: 404 });
  });

  return service;
}

function stored(
  request: Awaited<ReturnType<typeof buildEnvelopeWithAssisted>>,
) {
  return {
    ...request,
    owner_email: 'person@example.com',
    kdf_algorithm: '',
    kdf_params: {},
    salt: '',
    wrappers: request.wrappers!.map(w => ({ ...w, created_at: 0 })),
    created_at: 0,
    updated_at: 0,
  } as RecoverySecret;
}

beforeEach(() => {
  vi.mocked(getManagedAccount).mockResolvedValue({
    email: 'person@example.com',
  });
  vi.mocked(getManagedApiBase).mockReturnValue('https://portal.example/api');
  vi.mocked(managedFetch).mockReset();
});

it('a backup made for the account opens with the account alone', async () => {
  fakeService({ fresh: true });
  const request = await buildEnvelopeWithAssisted({
    secret: 'the-agent-secret',
    agentSubject: AGENT,
  });

  expect(request.wrappers).toHaveLength(1);
  expect(request.wrappers![0].wrapper_type).toBe('atomic-assisted');
  // The DEK and the secret never go to the service.
  const sent = vi
    .mocked(managedFetch)
    .mock.calls.map(([, init]) => String(init?.body ?? ''))
    .join('\n');
  expect(sent).not.toContain('the-agent-secret');

  const backup = stored(request);
  expect(hasAssistedWrapper(backup)).toBe(true);
  expect(await decryptEnvelopeWithAssisted(backup)).toBe('the-agent-secret');
});

it('an old sign-in is told to sign in again', async () => {
  fakeService({ fresh: false });
  const backup = stored(
    await buildEnvelopeWithAssisted({ secret: 's', agentSubject: AGENT }),
  );

  await expect(decryptEnvelopeWithAssisted(backup)).rejects.toBeInstanceOf(
    FreshSignInRequiredError,
  );
});

it('a build without an account service asks nobody', async () => {
  const { hasManagedApi } = await import('./api');
  const { getAccountProviders } = await import('./accountProviders');
  vi.mocked(hasManagedApi).mockReturnValueOnce(false);
  vi.mocked(managedFetch).mockClear();

  expect(await getAccountProviders()).toEqual({
    google: false,
    apple: false,
    github: false,
    assisted_recovery: false,
  });
  expect(managedFetch).not.toHaveBeenCalled();
});

it('a wrapper from a rotated key is re-wrapped with the current one', async () => {
  const service = fakeService({ fresh: true });
  const request = await buildEnvelopeWithAssisted({
    secret: 'the-agent-secret',
    agentSubject: AGENT,
  });
  expect(request.wrappers![0].kdf_params).toEqual({ key_id: 'key-1' });

  service.currentKey = 'key-2';
  expect(await decryptEnvelopeWithAssisted(stored(request))).toBe(
    'the-agent-secret',
  );

  await vi.waitFor(() => expect(service.appended).toHaveLength(1));
  const [rewrapped] = service.appended as {
    kdf_params: unknown;
    salt: string;
  }[];
  expect(rewrapped.kdf_params).toEqual({ key_id: 'key-2' });
  expect(rewrapped.salt).not.toBe(request.wrappers![0].salt);
});

it('an account that turned assisted recovery off gets no new wrapper', async () => {
  const service = fakeService({ fresh: true });
  const request = await buildEnvelopeWithAssisted({
    secret: 's',
    agentSubject: AGENT,
  });
  vi.mocked(getManagedAccount).mockResolvedValue({
    email: 'person@example.com',
    assisted_recovery_off: true,
  });
  service.currentKey = 'key-2';
  await decryptEnvelopeWithAssisted(stored(request));
  await new Promise(resolve => setTimeout(resolve, 20));
  expect(service.appended).toHaveLength(0);
});

it('a backup from before assisted recovery gets it with its recovery code', async () => {
  const service = fakeService({ fresh: true });
  const { buildEnvelopeV2, enableAssistedForBackup } =
    await import('./recovery');
  const { recoveryCode, request } = await buildEnvelopeV2({
    secret: 'the-agent-secret',
    agentSubject: AGENT,
  });
  // As it was stored before the service offered assisted recovery.
  const old = stored({
    ...request,
    wrappers: request.wrappers!.filter(
      w => w.wrapper_type !== 'atomic-assisted',
    ),
  });
  expect(hasAssistedWrapper(old)).toBe(false);
  service.appended.length = 0;

  await enableAssistedForBackup(old, recoveryCode);

  expect(service.appended).toHaveLength(1);
  // What the service would store: the old wrappers plus the new one.
  const withWrapper = {
    ...old,
    wrappers: [
      ...old.wrappers,
      { ...(service.appended[0] as object), created_at: 0 },
    ],
  } as RecoverySecret;
  expect(await decryptEnvelopeWithAssisted(withWrapper)).toBe(
    'the-agent-secret',
  );
});

it('a wrong recovery code adds nothing', async () => {
  const service = fakeService({ fresh: true });
  const { buildEnvelopeV2, enableAssistedForBackup } =
    await import('./recovery');
  const { request } = await buildEnvelopeV2({
    secret: 's',
    agentSubject: AGENT,
  });
  const old = stored({
    ...request,
    wrappers: request.wrappers!.filter(
      w => w.wrapper_type !== 'atomic-assisted',
    ),
  });
  service.appended.length = 0;

  await expect(
    enableAssistedForBackup(old, 'AAAA-BBBB-CCCC-DDDD'),
  ).rejects.toThrow();
  expect(service.appended).toHaveLength(0);
});
