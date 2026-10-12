/* eslint-disable no-console */
import chalk from 'chalk';
import { spawn } from 'node:child_process';
import { hostname } from 'node:os';
import {
  connectAgentUrl,
  enableLoro,
  publishAgentName,
  waitForGrant,
} from '@tomic/lib';
import { loadOrCreateLocalAgent } from '@tomic/lib/node';
import { store, serverUrl, KEY_TOOL } from '../store.js';

const flag = (args: string[], name: string): string | undefined => {
  const i = args.indexOf(name);

  return i === -1 ? undefined : args[i + 1];
};

function openInBrowser(url: string) {
  const opener =
    process.platform === 'darwin'
      ? 'open'
      : process.platform === 'win32'
        ? 'explorer'
        : 'xdg-open';

  try {
    spawn(opener, [url], { detached: true, stdio: 'ignore' })
      .on('error', () => undefined)
      .unref();
  } catch {
    // No browser to open: the printed link is enough.
  }
}

/**
 * `ad-generate connect`: give this machine its own key for the server in
 * atomic.config.json, approved in the app, so private ontologies can be read
 * without putting an agent secret in the config file (which often ends up in
 * a repository). The key lives in ~/.config/atomic-cli/.
 */
export const connectCommand = async (args: string[]) => {
  if (!serverUrl) {
    console.error(chalk.red('Set "serverUrl" in atomic.config.json first.'));
    process.exitCode = 1;

    return;
  }

  const local = await loadOrCreateLocalAgent(KEY_TOOL, serverUrl);
  const name = flag(args, '--name') ?? `ad-generate on ${hostname()}`;
  store.setAgent(local!.agent);

  // Resources arrive as Loro snapshots; the name lives on one.
  await enableLoro();
  await publishAgentName(store, name).catch(() => undefined);

  const link = connectAgentUrl(flag(args, '--app') ?? serverUrl, {
    publicKey: local!.publicKey,
    name,
  });

  console.log(
    chalk.cyan(`\nOpen this link to let "${name}" read your ontologies:\n`),
  );
  console.log(`  ${link}\n`);
  console.log('Waiting for you to click Allow...');
  openInBrowser(link);

  try {
    await waitForGrant(store, local!.agent.subject!);
  } catch (e) {
    console.error(chalk.red(e instanceof Error ? e.message : String(e)));
    process.exitCode = 1;

    return;
  }

  console.log(
    chalk.green(
      `\nConnected. The key is stored in ${local!.path}. Revoke it any time under Connected apps in your account settings.`,
    ),
  );
};
