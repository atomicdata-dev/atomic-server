import { server, useResource, useStore } from '@tomic/react';
import { createRoute } from '@tanstack/react-router';
import toast from 'react-hot-toast';
import { appRoute } from './RootRoutes';
import { pathNames, paths } from './paths';
import { useSettings } from '../helpers/AppSettings';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { constructOpenURL } from '../helpers/navigation';
import { Shell } from '../views/getting-started/chrome';
import { Logo } from '../components/Logo';
import { Button } from '../components/Button';
import { readTemplateDemo } from '../chunks/Templates/demoSession';
import { readDemoDrive } from '../components/DemoExitButton';
import { Row } from '../components/Row';
import { styled } from 'styled-components';
import { DriveTemplateSetup } from '../chunks/Templates/DriveTemplateSetup';
import { useEffect, type JSX } from 'react';

let previewIdentity: Promise<unknown> | undefined;

export const NewDriveRoute = createRoute({
  path: pathNames.newDrive,
  getParentRoute: () => appRoute,
  component: () => <NewDrivePage />,
});

// Reached from the managed portal's dashboard ("+ New drive"). The drive is
// created *here* rather than in the portal because the portal only ever holds
// a session cookie, never the agent's private key.
//
// It creates the drive and stops there. It used to also enroll the new drive
// in Cloud Server, which was right when hosting was what every account got and
// is wrong now: Cloud Server is the paid tier, and the default is a local-first
// drive with encrypted backup offered from the Sync page like any other drive.
//
// That leftover was not a cosmetic mismatch. Enrolling needs a node with free
// capacity, so creating a drive failed outright whenever the fleet was full —
// a 500 reported as "Could not enable backup" — and once plan limits are
// enforced it fails again with a 402 for anyone without a subscription. Neither
// has anything to do with making a drive.
function NewDrivePage(): JSX.Element {
  const { agent, drive, setDrive, setAgent } = useSettings();
  const store = useStore();
  const currentDrive = useResource(drive || undefined);
  const isDemo =
    drive === readTemplateDemo()?.drive || drive === readDemoDrive();
  const closeTarget =
    agent &&
    drive &&
    !isDemo &&
    !currentDrive.error &&
    currentDrive.isReady() &&
    currentDrive.hasClasses(server.classes.drive)
      ? drive
      : undefined;
  // Only the isolated preview build permits anonymous gallery entry.
  const preview =
    import.meta.env.VITE_E2E === 'true' &&
    new URLSearchParams(window.location.search).has('template_preview');
  const navigate = useNavigateWithTransition();
  useEffect(() => {
    if (agent) return;

    if (!preview) {
      navigate(paths.welcome);

      return;
    }

    let active = true;
    previewIdentity ??= import('../chunks/Demo/guestAgent')
      .then(({ ensureAgentForDemo }) => ensureAgentForDemo(store))
      .finally(() => {
        previewIdentity = undefined;
      });
    previewIdentity
      .then(() => {
        const guest = store.getAgent();
        if (active && guest) setAgent(guest);
      })
      .catch(() => toast.error('Could not open the preview. Please refresh.'));

    return () => {
      active = false;
    };
  }, [agent, navigate, preview, setAgent, store]);
  if (!agent) return <Shell />;

  return (
    <Shell>
      <SetupContent>
        <Row justify='space-between'>
          <Logo style={{ width: '14rem', maxWidth: '55%' }} />
          {closeTarget && (
            <Button
              subtle
              onClick={() => navigate(constructOpenURL(closeTarget))}
            >
              Close
            </Button>
          )}
        </Row>
        <DriveTemplateSetup
          onCreated={resource => {
            setDrive(resource.subject);
            toast.success('Drive created');
            navigate(constructOpenURL(resource.subject));
          }}
        />
      </SetupContent>
    </Shell>
  );
}

const SetupContent = styled.main`
  width: min(100%, 65rem);
  display: flex;
  flex-direction: column;
  gap: ${p => p.theme.size(6)};
`;
