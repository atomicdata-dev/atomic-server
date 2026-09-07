import {
  useBoolean,
  useNumber,
  useResource,
  useTitle,
  useString,
  Agent,
  generateKeyPair,
  server,
  core,
  useStore,
  type Server,
  SubtleCryptoProvider,
  JSCryptoProvider,
  type KeyPair,
  Resource,
} from '@tomic/react';

import { Button } from '../components/Button';
import { constructOpenURL } from '../helpers/navigation';
import { useSettings } from '../helpers/AppSettings';
import { ResourcePageProps } from './ResourcePage';
import { paths } from '../routes/paths';
import { Column } from '../components/Row';
import { useWelcomeLayoutEffect } from '../hooks/useWelcomeLayoutEffect';
import { Shell, Card, CardTitle, CtaButton } from './getting-started/chrome';
import { Logo } from '../components/Logo';

import { useId, useState, type JSX } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { fetchPrivateDriveSubject } from '@helpers/privateDrive';
import { saveAgentToIDB } from '@helpers/agentStorage';
import { Dialog, useDialog } from '@components/Dialog';
import { CodeBlock } from '@components/CodeBlock';
import { styled } from 'styled-components';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import Field from '@components/forms/Field';

/** A View that opens an invite */
function InvitePage({ resource }: ResourcePageProps): JSX.Element {
  const nameInputId = useId();
  const store = useStore();
  const [usagesLeft] = useNumber(resource, server.properties.usagesLeft);
  const [write] = useBoolean(resource, server.properties.write);
  const [description] = useString(resource, core.properties.description);
  // Use plain `useNavigate` rather than `useNavigateWithTransition`. The
  // transition wrapper chains navigations through
  // `document.startViewTransition` whose `finished` promise never resolves
  // in headless test contexts (no compositor), wedging the next
  // post-invite navigate. The invite redirect runs once on accept; not
  // animating it is fine.
  const baseNavigate = useNavigate();
  const navigate = (to: string) => baseNavigate({ to });
  const { agent, setAgent, setDrive } = useSettings();
  const agentResource = useResource(agent?.subject);
  const [agentTitle] = useTitle(agentResource, 15);
  const [redirectURL, setRedirectURL] = useState<string | undefined>(undefined);
  const [agentSecret, setAgentSecret] = useState<string | undefined>();
  const [agentName, setAgentName] = useState<string | undefined>(undefined);
  const [hasCopiedSecret, setHasCopiedSecret] = useState(false);
  const [isNewAgent, setIsNewAgent] = useState(false);

  const getRedirectDestination = async (
    redirect: Resource<Server.Redirect>,
  ): Promise<string | undefined> => {
    const destinationValue = (await redirect.get(
      server.properties.destination,
    )) as unknown;
    const redirectProps = redirect.props as Record<string, unknown>;

    return (
      (typeof destinationValue === 'string' ? destinationValue : undefined) ??
      (redirectProps[server.properties.destination] as string | undefined) ??
      (redirectProps.destination as string | undefined)
    );
  };

  const goToRedirect = (destination?: string, activated?: boolean) => {
    const url = destination ?? redirectURL;
    if (!url) return;
    queueMicrotask(() => {
      navigate(constructOpenURL(url));
      void store.fetchResourceFromServer(url).finally(() => {
        // The invite's own drive is already the active one — leave it alone.
        // Falling through here is what used to send an invitee straight back
        // to their private drive: they'd land on the shared resource with a
        // sidebar showing their own drive, and no live subscription to the
        // one they were invited to.
        if (activated) {
          return;
        }

        const signedIn = store.getAgent();

        if (!signedIn?.subject) {
          return;
        }

        void fetchPrivateDriveSubject(store, signedIn).then(home => {
          if (home) {
            setDrive(home);
          }
        });
      });
    });
  };

  /**
   * Persist everything needed after accepting an invite.
   *
   * The Agent keeps only IDENTITY: name, isA, and the `privateDrive` pointer.
   * The per-user index lists (`sharedWithMe`, `drives`) live on the PRIVATE
   * DRIVE — the home index — not on the Agent. So this writes two resources:
   *  1. the Agent (identity + pointer), then
   *  2. the personal drive (the lists).
   * Order matters: the Agent's `privateDrive` must be saved before the drive's
   * lists, so the sidebar can resolve agent → privateDrive → lists.
   *
   * Returns both drives the caller has to choose between: the invitee's own
   * `privateDrive`, and `hostDrive` — the drive the invited resource lives on,
   * which is the one they should land in.
   */
  const persistAgentAfterInvite = async (
    subject: string,
    destination: string | undefined,
    name?: string,
  ): Promise<{ privateDrive?: string; hostDrive?: string }> => {
    store.getResourceLoading(subject);
    let privateDriveSubject: string | undefined;
    let hostDriveSubject: string | undefined;

    try {
      // --- 1. Agent identity: name, isA, privateDrive pointer ---
      if (name?.trim()) {
        await agentResource.set(core.properties.name, name.trim());
      }

      const currentIsA =
        (await agentResource.get(core.properties.isA)) ?? ([] as string[]);

      if (!currentIsA.includes(core.classes.agent)) {
        await agentResource.set(core.properties.isA, [
          ...currentIsA,
          core.classes.agent,
        ]);
      }

      await agentResource.save();

      // The home is DERIVED from the agent's key, so it is the one drive this
      // flow must not invent. Minting a fresh one here and pointing the Agent
      // at it wrote the lists below to a drive nothing reads: the sidebar
      // resolves the home from the key (`usePrivateDrive`), not from the
      // pointer, so "Shared with me" stayed empty after accepting an invite.
      //
      // `ensurePrivateDrive` also seeds the switcher list and writes the
      // pointer for older clients, which is why neither happens here anymore.
      // Saved first, so it links against a complete Agent rather than a
      // half-written one.
      // No literal for the unnamed case: `ensurePrivateDrive` already
      // defaults it, inside the library, where the i18n extractor cannot turn
      // a plain string into an injected hook in this non-component function.
      const driveResource = name?.trim()
        ? await store.ensurePrivateDrive(`${name.trim()}'s Drive`)
        : await store.ensurePrivateDrive();
      privateDriveSubject = driveResource.subject;

      // --- 2. Home-index lists, stored on the PRIVATE DRIVE ---
      if (destination) {
        // sharedWithMe is what the sidebar's "Shared with me" panel reads.
        // Set it first so a failure in the drive-bookmark code below doesn't
        // bubble to the outer catch and skip the drive `save()`.
        driveResource.push(core.properties.sharedWithMe, [destination], true);

        // A child invite grants access to that child, not its private parents.
        // Only bookmark a drive we can already read; never fetch inaccessible
        // ancestors just to populate the switcher. Shared with me holds the
        // invited child regardless of whether its host drive is readable.
        try {
          await store.fetchResourceFromServer(destination);
          let target = store.resources.get(destination);
          const visited = new Set<string>();
          let hostDrive: string | undefined;

          while (
            target?.isReady() &&
            !target.error &&
            !visited.has(target.subject)
          ) {
            visited.add(target.subject);

            if (target.hasClasses(server.classes.drive)) {
              hostDrive = target.subject;
              break;
            }

            const parent = target.get(core.properties.parent);
            target =
              typeof parent === 'string'
                ? store.resources.get(parent)
                : undefined;
          }

          if (hostDrive && hostDrive !== privateDriveSubject) {
            hostDriveSubject = hostDrive;
            driveResource.push(server.properties.drives, [hostDrive], true);
          }
        } catch (e) {
          console.warn(
            '[invite] could not bookmark host drive (sharedWithMe still set):',
            e,
          );
        }
      }

      await driveResource.save();
    } catch (e) {
      store.notifyError(
        e instanceof Error
          ? e
          : new Error('Failed to persist agent after accepting invite'),
      );
    }

    return { privateDrive: privateDriveSubject, hostDrive: hostDriveSubject };
  };

  /**
   * Make the invite's drive the active one, so the sidebar shows what the
   * invitee was actually invited to. Falls back to their own drive when the
   * destination's drive can't be resolved (a bare resource, or the ancestry
   * walk failed) — which is also the new-agent case, where `drive` would
   * otherwise still be `baseURL`. Reports whether it set anything, so
   * `goToRedirect` knows not to overwrite it.
   */
  const activateDrive = (drives: {
    privateDrive?: string;
    hostDrive?: string;
  }): boolean => {
    const target = drives.hostDrive ?? drives.privateDrive;

    if (!target) {
      return false;
    }

    setDrive(target);

    return true;
  };

  const [dialogProps, show, hide] = useDialog({
    onSuccess: async () => {
      setAgentSecret(undefined);
      const agentSubject = agent?.subject;

      if (!agentSubject) {
        goToRedirect();

        return;
      }

      const drives = await persistAgentAfterInvite(
        agentSubject,
        redirectURL,
        agentName,
      );

      goToRedirect(undefined, activateDrive(drives));
    },
  });

  // When the Invite is accepted, a new Agent might be created client-side.
  async function handleNew() {
    try {
      const keypair = await generateKeyPair();

      let cryptoKeyPair: CryptoKeyPair | undefined;

      try {
        cryptoKeyPair =
          await SubtleCryptoProvider.createKeysFromKeyPair(keypair);
      } catch {
        // SubtleCrypto doesn't support Ed25519 in this environment.
        // We'll use JSCryptoProvider as a fallback below.
      }

      const provider = cryptoKeyPair
        ? new SubtleCryptoProvider(cryptoKeyPair)
        : new JSCryptoProvider(keypair.privateKey);

      const subject = `did:ad:agent:${keypair.publicKey}`;
      const newAgent = new Agent(provider, subject);

      // Same reason as in `handleAccept`: a WebCrypto key cannot reproduce
      // this later, and this agent goes into the store before that runs.
      newAgent.privateDrive = await Agent.privateDriveSubjectFromSecret(
        Agent.buildSecret(keypair.privateKey, subject),
      );
      store.setAgent(newAgent);

      // Create the initial Agent resource using the Store instance,
      // otherwise it won't have a store bound (and `.save()` will fail).
      const newAgentResource = store.getResourceLoading(subject, {
        newResource: true,
      });
      await newAgentResource.set(core.properties.publicKey, keypair.publicKey);
      await newAgentResource.set(core.properties.isA, [core.classes.agent]);
      await newAgentResource.save();

      setAgent(newAgent);
      handleAccept({ crypto: cryptoKeyPair, real: keypair });
    } catch (error) {
      store.notifyError(error);
    }
  }

  const handleAccept = async (keys?: {
    crypto?: CryptoKeyPair;
    real: KeyPair;
  }) => {
    const inviteURL = new URL(resource.subject);
    const redirect = await store.postToServer<Server.Redirect>(inviteURL.href);

    if (redirect.error) {
      store.notifyError(redirect.error);

      return;
    }

    const destination = await getRedirectDestination(redirect);

    if (!destination) {
      store.notifyError(
        new Error('Invite accepted, but no destination was returned.'),
      );

      return;
    }

    if (keys) {
      const newAgentSubject = `did:ad:agent:${keys.real.publicKey}`;
      const secret = Agent.buildSecret(
        keys.real.privateKey,
        newAgentSubject,
        destination,
      );

      const provider = keys.crypto
        ? new SubtleCryptoProvider(keys.crypto)
        : new JSCryptoProvider(keys.real.privateKey);
      const newAgent = new Agent(provider, newAgentSubject, destination);

      // The home drive is the signature this key makes over its genesis cert,
      // and a WebCrypto key signs differently every time — so it can only be
      // computed here, while the raw key is still in hand, and must then be
      // carried. Skipping it left the agent permanently unable to name its own
      // home: the sidebar's home-index panels resolve the drive from the key,
      // found nothing, and rendered as though nothing had ever been shared.
      newAgent.privateDrive = await Agent.privateDriveSubjectFromSecret(secret);

      // Stored as the secret, not as the keypair. The keypair overload has
      // nothing to derive the above from and writes it as undefined, which is
      // what threw it away a line after it was computed. This path still
      // prefers the non-extractable keypair, and it also covers the JS-crypto
      // fallback, which previously persisted no agent at all.
      // `adoptOnDevice: false` keeps this to storage. Signing in is the moment
      // a device takes on an identity; opening an invite link is not — this
      // runs on a desktop that may already hold its owner's agent, and the
      // embedded node should not start signing as whoever accepted an invite.
      await saveAgentToIDB(secret, { adoptOnDevice: false });

      setAgentSecret(secret);
      setAgent(newAgent);
      setIsNewAgent(true);
    } else {
      setIsNewAgent(false);
      setRedirectURL(destination);

      void (async () => {
        const drives = await persistAgentAfterInvite(
          agentSubject!,
          destination,
          undefined,
        );

        goToRedirect(destination, activateDrive(drives));
      })();

      return;
    }

    // New agent: show dialog (secret, name) then on Continue we persist and redirect
    setRedirectURL(destination);
    show();
  };

  const agentSubject = agent?.subject;

  useWelcomeLayoutEffect();

  // Extract the resource name from the server-generated description
  // Format: "Stateless invite to edit/view the resource: ResourceName"
  const resourceName = description?.split(': ').pop();

  return (
    <>
      <Shell>
        <Card>
          <LogoWrap>
            <Logo style={{ width: 180, maxWidth: '100%' }} />
          </LogoWrap>
          <CardTitle>
            You've been invited to {write ? 'edit' : 'view'}
            {resourceName ? ` "${resourceName}"` : ''}
          </CardTitle>
          {usagesLeft === 0 ? (
            <DescriptionWrap>
              Sorry, this invite has no usages left. Ask for a new one.
            </DescriptionWrap>
          ) : (
            <Column gap='0.75rem'>
              {agentSubject ? (
                <CtaButton
                  data-test='accept-existing'
                  onClick={() => handleAccept()}
                >
                  Accept as {agentTitle}
                </CtaButton>
              ) : (
                <>
                  <CtaButton data-test='accept-new' onClick={handleNew}>
                    Create account and accept
                  </CtaButton>
                  <CtaButton
                    data-test='accept-sign-in'
                    onClick={() => navigate(paths.agentSettings)}
                    subtle
                  >
                    I already have an account
                  </CtaButton>
                </>
              )}
            </Column>
          )}
        </Card>
      </Shell>
      <Dialog {...dialogProps} disableLightDismiss>
        <Dialog.Title>
          <h1>Agent created!</h1>
        </Dialog.Title>
        <Dialog.Content>
          <Field label='Agent Name' fieldId={nameInputId}>
            <InputWrapper>
              <InputStyled
                type='text'
                value={agentName ?? ''}
                onChange={e => setAgentName(e.target.value)}
                id={nameInputId}
                spellCheck='false'
                placeholder='Enter a name'
              />
            </InputWrapper>
          </Field>
          {isNewAgent && agentSecret && (
            <Field label='Agent Secret'>
              <p>
                IMPORTANT! Below is your agent secret, you use this to login.
                Save it somewhere safe, the secret will not be show again and if
                you lose it you will not be able to access this user again.
              </p>
              <StyledCodeBlock
                wordWrap
                content={agentSecret}
                onCopy={() => setHasCopiedSecret(true)}
              />
            </Field>
          )}
        </Dialog.Content>
        <Dialog.Actions>
          <Button
            onClick={() => hide(true)}
            disabled={isNewAgent && !hasCopiedSecret}
          >
            {isNewAgent
              ? hasCopiedSecret
                ? 'Continue'
                : 'Copy secret to continue'
              : 'Continue'}
          </Button>
        </Dialog.Actions>
      </Dialog>
    </>
  );
}

export default InvitePage;

const LogoWrap = styled.div`
  text-align: center;
  margin-bottom: ${p => p.theme.size(4)};
`;

const DescriptionWrap = styled.div`
  color: ${p => p.theme.colors.textLight};
  text-align: center;
  margin-bottom: ${p => p.theme.size(5)};
`;

const StyledCodeBlock = styled(CodeBlock)`
  word-break: break-word;

  & button {
    top: ${p => p.theme.size(1)};
    right: ${p => p.theme.size(1)};
  }
`;
