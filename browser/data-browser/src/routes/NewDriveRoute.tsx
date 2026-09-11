import { getManagedPortalUrl } from '../helpers/managed/cloudSync';
import { FormEvent, useEffect, useState, type JSX } from 'react';
import { createRoute } from '@tanstack/react-router';
import { useStore } from '@tomic/react';
import toast from 'react-hot-toast';
import { appRoute } from './RootRoutes';
import { pathNames, paths } from './paths';
import { useSettings } from '../helpers/AppSettings';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { constructOpenURL } from '../helpers/navigation';
import { Main } from '../components/Main';
import { ContainerNarrow } from '../components/Containers';
import { Button } from '../components/Button';
import { Column } from '../components/Row';
import Field from '../components/forms/Field';
import { InputWrapper, InputStyled } from '../components/forms/InputStyles';

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
  const store = useStore();
  const { agent, setDrive } = useSettings();
  const navigate = useNavigateWithTransition();
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | undefined>();

  useEffect(() => {
    if (!agent) {
      navigate(paths.welcome);
    }
  }, [agent, navigate]);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const trimmed = name.trim();
    const agentSubject = agent?.subject;

    if (!trimmed || busy || !agentSubject) return;

    setBusy(true);
    setError(undefined);

    try {
      const resource = await store.createDrive(trimmed, {
        personal: false,
        localOnly: !!getManagedPortalUrl(),
      });
      store.notifyResourceManuallyCreated(resource);
      setDrive(resource.subject);

      toast.success('Drive created');
      navigate(constructOpenURL(resource.subject));
    } catch (err) {
      const asError =
        err instanceof Error ? err : new Error('Could not create the drive.');
      store.notifyError(asError);
      setError(asError);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Main>
      <ContainerNarrow>
        <Column gap='1.5rem'>
          <h1>New drive</h1>
          <form onSubmit={handleSubmit}>
            <Column gap='1rem'>
              <Field required label='Name' error={error}>
                <InputWrapper>
                  <InputStyled
                    value={name}
                    onChange={e => setName(e.target.value)}
                    placeholder='My Drive'
                    autoFocus
                  />
                </InputWrapper>
              </Field>
              <Button type='submit' disabled={busy || !name.trim()}>
                {busy ? 'Creating…' : 'Create drive'}
              </Button>
            </Column>
          </form>
        </Column>
      </ContainerNarrow>
    </Main>
  );
}
