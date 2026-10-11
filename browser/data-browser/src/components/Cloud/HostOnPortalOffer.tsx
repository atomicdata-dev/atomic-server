import { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { styled } from 'styled-components';
import { useStore } from '@tomic/react';
import { Button } from '../Button';
import { ConfirmationDialog } from '../ConfirmationDialog';
import { HostingConsentNotice } from './HostingConsentNotice';
import { useSettings } from '../../helpers/AppSettings';
import { driveBillingUrl } from '../../helpers/driveBillingUrl';
import { fetchManagedInfo } from '../../helpers/managedServer';
import { driveHasCloudEnrollment } from '../../helpers/managed/cloudSync';
import { HostingPaymentRequiredError } from '../../helpers/managed/enrollment';
import {
  hostDriveOnPortal,
  knownPortalUrl,
  shouldOfferPortalHosting,
} from '../../helpers/managed/hostOnPortal';
import { isOriginWithoutNode } from '../../helpers/originNode';
import { openExternal } from '../../helpers/openExternal';
import { serverURLStorage } from '../../helpers/serverURLStorage';

/**
 * "Host on atomic.place" for a drive that lives nowhere but here (and on a
 * server the person did not choose): the way to make a later secret sign-in on
 * any other instance find it by itself.
 *
 * It is the Sync page's Cloud Server enrollment, started from here: it asks
 * for the hosting consent first, then the portal's own sign-in (email), then
 * hosts the drive. It hides itself once the drive is hosted, or when it was
 * never applicable (see {@link shouldOfferPortalHosting}).
 */
export function HostOnPortalOffer({
  drive,
  onClose,
}: {
  drive: string;
  onClose: () => void;
}) {
  const store = useStore();
  const { setServer, baseURL } = useSettings();
  const [offer, setOffer] = useState<'checking' | 'yes' | 'no'>('checking');
  const [asking, setAsking] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;

    void fetchManagedInfo(baseURL)
      .catch(() => null)
      .then(async info => {
        // An unreadable enrollment list is not evidence of hosting.
        const enrolled = await driveHasCloudEnrollment(drive).catch(
          () => false,
        );

        return shouldOfferPortalHosting({
          portalUrl: knownPortalUrl(info),
          serverExplicitlyChosen: serverURLStorage.wasExplicitlyChosen(),
          serverManaged: !!info?.managed,
          enrolled,
        });
      })
      .then(yes => {
        if (cancelled) return;

        setOffer(yes ? 'yes' : 'no');

        if (!yes) onClose();
      });

    return () => {
      cancelled = true;
    };
    // `onClose` is a new function each render; the check runs per drive.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [drive, baseURL]);

  async function host() {
    const agentSubject = store.getAgent()?.subject;

    if (!agentSubject || busy) return;

    setBusy(true);

    try {
      const serverUrl = store.getServerUrl();
      const info = await fetchManagedInfo(baseURL).catch(() => null);
      const outcome = await hostDriveOnPortal({
        store,
        drive,
        agentSubject,
        setServer,
        managedInfo: info,
        hostingConsentAccepted: true,
        sourceServer:
          !store.isLocalOnlyDrive(drive) &&
          serverUrl &&
          !isOriginWithoutNode(serverUrl)
            ? serverUrl
            : undefined,
      });

      if (outcome.status === 'hosted') {
        toast.success('Your workspace is now hosted on atomic.place.');
        onClose();
      } else if (outcome.status === 'cancelled') {
        toast('Sign-in wasn’t completed — hosting setup was cancelled.');
      } else {
        toast.error('No atomic.place portal is configured for this server.');
      }
    } catch (e) {
      const portal = knownPortalUrl();

      if (e instanceof HostingPaymentRequiredError && portal) {
        await openExternal(driveBillingUrl(portal, drive));
      } else {
        store.notifyError(e as Error);
      }
    } finally {
      setBusy(false);
    }
  }

  if (offer !== 'yes') return null;

  return (
    <Card data-testid='host-on-portal-offer'>
      <p>
        This workspace is only on this device and your server. Host it on
        atomic.place and signing in with your secret finds it anywhere.
      </p>
      <Actions>
        <Button
          data-testid='host-on-portal'
          onClick={() => setAsking(true)}
          disabled={busy}
        >
          {busy ? 'Hosting…' : 'Host on atomic.place'}
        </Button>
        <Button subtle onClick={onClose}>
          Not now
        </Button>
      </Actions>
      <ConfirmationDialog
        title='Host on atomic.place'
        confirmLabel='Agree and host'
        show={asking}
        bindShow={setAsking}
        onConfirm={() => void host()}
      >
        <p>
          <HostingConsentNotice />
        </p>
        <p>
          You will be asked for your email to sign in to atomic.place first.
        </p>
      </ConfirmationDialog>
    </Card>
  );
}

const Card = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.6rem;
  max-width: 24rem;
  padding: 0.8rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  background: ${p => p.theme.colors.bg};
  box-shadow: ${p => p.theme.boxShadowSoft};
  color: ${p => p.theme.colors.text};

  & p {
    margin: 0;
    white-space: normal;
  }
`;

const Actions = styled.div`
  display: flex;
  gap: 0.5rem;
`;
