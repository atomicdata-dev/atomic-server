// @wc-ignore-file
import {
  setup,
  setupDeclaration,
  credentialLink,
} from '../../../../../integrations/github-issues/setup';
import type { SetupAdapter } from './types';

/** Explicit migration adapter: the legacy installer remains host code until its effects migrate. */
const github: SetupAdapter = {
  id: 'github-issues',
  icon: '🐙',
  declaration: setupDeclaration,
  defaults: workspace => ({ destination: workspace ?? '' }),
  choices: async (lookup, { store, drive }) => {
    if (lookup !== 'destinations') throw new Error('Unknown setup lookup');
    const { compatibleTables } =
      await import('../../../../../integrations/github-issues/atomic');

    return (await compatibleTables(store, drive)).map(t => ({
      value: t.subject,
      label: t.name,
    }));
  },
  credential: {
    label: 'GitHub token',
    description:
      'Select this repository and grant Issues read/write access. Your token is stored on AtomicServer, outside the setup arguments. Create the atomic:doing label in GitHub to use the Doing column.',
    link: args => credentialLink(args.repository),
    linkLabel: 'Create GitHub token',
  },
  prepare: setup,
  connect: async (raw, token, { store, drive }) => {
    const args = setup(raw);
    const [{ install }, { default: source }] = await Promise.all([
      import('../../../../../integrations/github-issues/atomic'),
      import('../../../../../integrations/github-issues/plugin.js?raw'),
    ]);
    const result = await install(
      store,
      drive,
      args.repository,
      source,
      token,
      args.destination || undefined,
    );

    return { subject: result.table };
  },
};
const adapters = [github];

export function listAppSetups() {
  return adapters.map(({ id, declaration }) => ({ id, ...declaration }));
}
export function getAppSetup(id: string): SetupAdapter {
  const adapter = adapters.find(a => a.id === id);
  if (!adapter) throw new Error('This app has no registered setup action');

  return adapter;
}
