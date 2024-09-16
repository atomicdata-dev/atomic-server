export function getPackagemanager(): string {
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

export function getRunCommand(packageManager: string = 'npm', command: string) {
  if (packageManager === 'npm' && command !== 'start') {
    return `npm run ${command}`;
  }

  return `${packageManager} ${command}`;
}

export function startCommand(template: string, packageManager: string) {
  if (template === 'sveltekit-site') {
    return getRunCommand(packageManager, 'dev');
  }

  return getRunCommand(packageManager, 'start');
}
