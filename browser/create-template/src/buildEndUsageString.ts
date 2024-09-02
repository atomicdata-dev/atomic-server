import chalk from 'chalk';

export function buildEndUsageString(template: string, folder: string): string {
  const packageManager = getPackagemanager();

  const commands = [
    chalk.blue('\nTo continue run the following commands:'),
    `cd ${folder}`,
    `${packageManager} install`,
    runCommand(packageManager, 'update-ontologies'),
    startCommand(template, packageManager),
  ];

  return commands.join('\n');
}

function getPackagemanager(): string {
  const userAgent = process.env.npm_config_user_agent;
  const defaultPackageManager = 'npm';

  if (!userAgent) {
    return defaultPackageManager;
  }

  if (userAgent.includes('yarn')) {
    return 'yarn';
  } else if (userAgent.includes('pnpm')) {
    return 'pnpm';
  }

  return defaultPackageManager;
}

function runCommand(packageManager: string = 'npm', command: string) {
  if (packageManager === 'npm' && command !== 'start') {
    return `npm run ${command}`;
  }

  return `${packageManager} ${command}`;
}

function startCommand(template: string, packageManager: string) {
  if (template === 'sveltekit-site') {
    return runCommand(packageManager, 'dev');
  }

  return runCommand(packageManager, 'start');
}
