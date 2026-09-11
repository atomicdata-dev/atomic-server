// @wc-ignore-file
import { parseSetupDeclaration } from '../../../../../browser/lib/src/plugin-setup';
import { requireInstallationServer } from '../../../../../browser/lib/src/plugin-installation';
import {
  setup,
  setupDeclaration,
  credentialLink,
} from '../../../../../integrations/github-issues/setup';
import type { SetupAdapter } from './types';
import {
  setup as notionSetup,
  setupDeclaration as notionDeclaration,
} from '../../../../../integrations/notion/setup';

/** Explicit migration adapter: the legacy installer remains host code until its effects migrate. */
const github: SetupAdapter = {
  id: 'github-issues',
  icon: '🐙',
  declaration: parseSetupDeclaration(setupDeclaration),
  preflight: ({ store, drive }) => requireInstallationServer(store, drive),
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
    const { installGitHub } =
      await import('../../chunks/PluginRuns/githubInstaller');
    const result = await installGitHub(
      store,
      drive,
      args.repository,
      token,
      args.destination || undefined,
    );

    return { subject: result.table };
  },
};
const notion: SetupAdapter = {
  id: 'notion',
  icon: '📓',
  declaration: parseSetupDeclaration(notionDeclaration),
  preflight: ({ store, drive }) => requireInstallationServer(store, drive),
  choices: async () => {
    throw new Error('Unknown setup lookup');
  },
  prepare: notionSetup,
  credential: {
    label: 'Notion connection token',
    description:
      'Stored on your AtomicServer, outside setup arguments. Compatibility notes appear before you approve any sync.',
  },
  connect: async (raw, token, { store, drive }) => {
    const args = notionSetup(raw);
    const { installNotion } =
      await import('../../chunks/PluginRuns/notionInstaller');
    const result = await installNotion(store, drive, args.dataSource, token);

    return { subject: result.table };
  },
};
const adapters = [github, notion];

export function listAppSetups() {
  return adapters.map(({ id, declaration }) => ({ id, ...declaration }));
}
export function getAppSetup(id: string): SetupAdapter {
  const adapter = adapters.find(a => a.id === id);
  if (!adapter) throw new Error('This app has no registered setup action');

  return adapter;
}
