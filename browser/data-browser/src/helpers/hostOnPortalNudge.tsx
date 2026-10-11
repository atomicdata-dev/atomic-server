import toast from 'react-hot-toast';
import { HostOnPortalOffer } from '../components/Cloud/HostOnPortalOffer';

/**
 * Right after a secret sign-in that found the drive hosted nowhere: offer to
 * host it on atomic.place. The offer checks again itself and closes when it
 * does not apply.
 */
export function hostOnPortalNudge(drive: string) {
  const id = 'host-on-portal';

  toast.custom(
    () => <HostOnPortalOffer drive={drive} onClose={() => toast.dismiss(id)} />,
    { id, duration: Infinity },
  );
}
