import type { ManagedEnrollmentSummary } from './enrollmentApi';
import type { VaultEnrollment } from './vault';

/** Service receipts describe copies, not this device's current connection. */
export function driveHostingState(
  local: boolean,
  server?: Pick<ManagedEnrollmentSummary, 'status' | 'resource_count'>,
  vault?: Pick<VaultEnrollment, 'status' | 'last_backup_at'>,
): string[] {
  const states: string[] = [];

  switch (server?.status) {
    case /* @wc-ignore */ 'Active':
      states.push((server.resource_count ?? 0) > 0 ? 'Server' : 'Server setup');
      break;
    case /* @wc-ignore */ 'Pending':
      states.push('Server setup');
      break;
    case /* @wc-ignore */ 'Suspended':
      states.push('Server paused');
      break;
    case /* @wc-ignore */ 'Error':
      states.push('Server error');
      break;
    case undefined:
    case /* @wc-ignore */ 'Disabled':
      break;
    default:
      states.push('Server unknown');
  }

  if (!states.length) states.push(local ? 'Local' : 'Remote');

  if (vault?.status === /* @wc-ignore */ 'active') {
    states.push(vault.last_backup_at ? 'Vault' : 'Vault setup');
  } else if (vault && vault.status !== /* @wc-ignore */ 'disabled') {
    states.push('Vault paused');
  }

  return states;
}
