import { dbgEnrollCall } from '../../helpers/managed/api';
import type { Store } from '@tomic/react';
import { fetchManagedInfo } from '../../helpers/managedServer';
import { getManagedEnrollments } from '../../helpers/managed/enrollmentApi';
import { localAgentIsDisposable } from '../../helpers/managed/reconcile';
import { getManagedAccount } from '../../helpers/managed/session';
import { prepareDriveSharing } from '../../helpers/managed/prepareDriveSharing';
import { sameOrigin } from '../../helpers/serverUrl';

/** Make the home index writable locally before adding a browser-only drive. */
export async function prepareTemplateDrive(store: Store): Promise<void> {
  const serverUrl = store.getServerUrl();
  const info = await fetchManagedInfo(serverUrl);
  if (!info.managed) return;

  const agent = store.getAgent();
  if (!agent) return; // createDrive reports the missing identity.
  const home = await agent.privateDriveSubject();
  if (store.isLocalOnlyDrive(home)) return;

  // A demo guest has no account, so nothing can be hosted for it, and asking
  // the control plane only fails with "Sign in". Leaving the demo lands the
  // guest in this gallery with such a home. Its home was never on the
  // server either (only a real signup creates one there), so there is no
  // server copy to verify against: asking the node for its inventory just
  // times out. Its home lives on this device only. A real account without a
  // session still has to sign in: its home may be hosted.
  if (
    agent.subject &&
    !(await getManagedAccount()) &&
    (await localAgentIsDisposable(store, agent.subject))
  ) {
    store.registerLocalOnlyDrive(home);

    return;
  }

  dbgEnrollCall('prepareTemplateDrive');
  const enrollments = await getManagedEnrollments(true);
  const enrolledHereOrUnknown = enrollments.some(
    enrollment =>
      enrollment.drive_subject === home &&
      enrollment.status !== 'Disabled' &&
      (!enrollment.http_origin ||
        sameOrigin(enrollment.http_origin, serverUrl)),
  );
  if (enrolledHereOrUnknown) return;

  const enrolledElsewhere = enrollments.some(
    enrollment =>
      enrollment.drive_subject === home && enrollment.status !== 'Disabled',
  );
  if (enrolledElsewhere)
    throw new Error(
      'This workspace is hosted on another device. Connect to it before creating a drive.',
    );

  await prepareDriveSharing(store, home, enrollments);
}
