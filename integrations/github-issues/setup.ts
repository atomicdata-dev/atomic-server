// @wc-ignore-file
import {
  validateSetupArguments,
  type SetupDeclaration,
} from '../../browser/lib/src/plugin-setup.js';

/** Package-owned declaration. Used unchanged by the form and assistant discovery. */
export const setupDeclaration: SetupDeclaration = {
  title: 'Connect GitHub',
  description:
    'Sync issue titles, descriptions and status with a kanban board. Review the first import before enabling background sync.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    required: ['repository'],
    properties: {
      repository: {
        type: 'string',
        title: 'Repository',
        description: 'The repository to connect, in owner/repository format.',
        minLength: 3,
      },
      destination: {
        type: 'string',
        title: 'Sync into',
        description:
          'Choose an existing compatible task table, or create an issue board.',
        'x-atomic': {
          widget: 'choice',
          lookup: 'destinations',
          emptyLabel: 'New issue board',
        },
      },
    },
  },
};

/** Pure setup normalization. No credentials, storage, network or schedule activation. */
export function setup(raw: unknown) {
  const args = validateSetupArguments(setupDeclaration, raw);
  const repository = String(args.repository).trim();
  if (!/^[a-zA-Z0-9-]+\/[a-zA-Z0-9_.-]+$/.test(repository))
    throw new Error('Enter a repository as owner/repository.');

  return {
    repository,
    destination: typeof args.destination === 'string' ? args.destination : '',
  };
}

export function credentialLink(repository: unknown) {
  const url = new URL('https://github.com/settings/personal-access-tokens/new');
  url.search = new URLSearchParams({
    name: 'Atomic issue sync',
    description: 'Two-way GitHub issue sync with Atomic',
    expires_in: '30',
    issues: 'write',
  }).toString();
  const match =
    typeof repository === 'string' &&
    repository.trim().match(/^([a-zA-Z0-9-]+)\/[a-zA-Z0-9_.-]+$/);
  if (match) url.searchParams.set('target_name', match[1]);

  return url.toString();
}
