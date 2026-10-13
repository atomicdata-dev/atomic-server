import { useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { Button } from './Button';
import { ScanCodeButton } from './ConnectToDeviceForm';
import { PairingCode } from './PairingCode';
import { cardSurface } from './cardSurface';
import { classifyConnectInput } from '../helpers/connectInput';
import { deliverDeepLink } from '../helpers/deepLinkQueue';
import { probeServer } from '../helpers/probeServer';

const SECTION_ID = 'connect-device';
const INPUT_ID = 'connect-device-input';

/**
 * Bring the Connect a device section into view and put the cursor in its box.
 * Used by anything that ends in "connect a device" (a missing workspace, a
 * sync problem) so they all lead to the same place.
 */
export function focusConnectDevice(): void {
  const section = document.getElementById(SECTION_ID);

  if (!section) return;

  section.scrollIntoView({ behavior: 'smooth', block: 'start' });
  document.getElementById(INPUT_ID)?.focus({ preventScroll: true });
}

interface ConnectDeviceProps {
  /** The node a pairing code should name (hex), or null when none is known. */
  pairNodeDid: string | null;
  /** Whether to offer this device's own code. Existing gating, decided by the page. */
  showPairing: boolean;
  /** This app is itself a node (desktop or mobile), so it can take a code. */
  canTakeCode: boolean;
  /** The address a browser tab reads from, named when showing its code. */
  serverName: string;
  onAddServer: (url: string) => void;
}

/**
 * The one place to connect another device, always in the same spot below the
 * device list.
 *
 * Two halves of the same act. "Show this device" is the code another device
 * scans. "Add a device" takes one thing, a pairing code or the address of an
 * always-on device, and works out which it is. A code only routes and grants
 * nothing, so showing it is safe.
 *
 * A browser tab is not a node and cannot take a code, so there a pasted code
 * is answered with where it can be entered instead of being refused silently.
 */
export function ConnectDevice({
  pairNodeDid,
  showPairing,
  canTakeCode,
  serverName,
  onAddServer,
}: ConnectDeviceProps): JSX.Element {
  const [input, setInput] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function connect(raw: string) {
    const parsed = classifyConnectInput(raw);

    if (parsed.kind === 'empty') return;

    if (parsed.kind === 'code') {
      if (!canTakeCode) {
        setMessage(
          'This looks like a pairing code. A browser tab can’t take one. Enter it on a device that runs the app, or type a server address here.',
        );

        return;
      }

      // The same path a scanned deep link takes: validate, remember the peer
      // and start a sync.
      deliverDeepLink(parsed.code);
    } else if (parsed.kind === 'server') {
      setBusy(true);
      setMessage(null);

      const probe = await probeServer(parsed.url);

      setBusy(false);

      if (probe !== 'node') {
        setMessage(
          probe === 'unreachable'
            ? 'Could not reach that address.'
            : 'That address answers, but it is not an AtomicServer.',
        );

        return;
      }

      onAddServer(parsed.url);
    } else {
      setMessage(
        canTakeCode
          ? 'That is not a pairing code or a server address.'
          : 'That is not a server address.',
      );

      return;
    }

    setInput('');
    setMessage(null);
  }

  return (
    <Section id={SECTION_ID} tabIndex={-1} data-testid='connect-device'>
      <Title>Connect a device</Title>
      <Note>
        {showPairing
          ? 'Codes only route. Your key still decides what syncs.'
          : 'An always-on device has an address. One you carry has a code.'}
      </Note>
      <Card>
        {showPairing && pairNodeDid && (
          <Side data-testid='connect-device-show'>
            <Label>Show this device</Label>
            <Hint>
              {canTakeCode
                ? 'Scan this from your other device, or copy the code.'
                : `Scan from your other device to sync with ${serverName}.`}
            </Hint>
            <Centered>
              <PairingCode nodeDid={pairNodeDid} />
            </Centered>
          </Side>
        )}
        {showPairing && pairNodeDid && <Divider aria-hidden />}
        <Side data-testid='connect-device-add'>
          <Label>Add a device</Label>
          <Hint>
            {canTakeCode
              ? 'Paste a pairing code, or type the address of an always-on device.'
              : 'Type the address of an always-on device.'}
          </Hint>
          <ScanCodeButton onCode={code => void connect(code)} />
          <Form
            onSubmit={e => {
              e.preventDefault();
              if (!busy) void connect(input);
            }}
          >
            <Input
              id={INPUT_ID}
              autoComplete='off'
              autoCapitalize='none'
              spellCheck={false}
              aria-label='Pairing code or server address'
              placeholder='Code or server address'
              value={input}
              onChange={e => {
                setInput(e.target.value);
                setMessage(null);
              }}
            />
            <Button type='submit' disabled={!input.trim() || busy}>
              Connect
            </Button>
          </Form>
          {message && (
            <Message role='alert' data-testid='connect-device-message'>
              {message}
            </Message>
          )}
          <DocsLink
            href='https://docs.atomicdata.dev/atomicserver/installation.html'
            target='_blank'
            rel='noopener'
          >
            How to run your own server
          </DocsLink>
        </Side>
      </Card>
    </Section>
  );
}

const Section = styled.section`
  margin-bottom: 2rem;
  scroll-margin-top: 1rem;

  &:focus {
    outline: none;
  }
`;

const Title = styled.h2`
  font-size: 1.1rem;
  margin-bottom: 0.8rem;
`;

const Note = styled.p`
  margin: 0 0 0.6rem;
  color: ${p => p.theme.colors.textLight};
  font-size: 0.82rem;
`;

/** The halves side by side: one card, not two. */
const Card = styled.div`
  ${cardSurface}
  align-items: stretch;
  gap: 1.5rem;

  /* Below this the halves read better stacked; the divider turns with them. */
  @media (max-width: 40rem) {
    flex-direction: column;
    gap: 1.1rem;
  }
`;

const Side = styled.div`
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 0.6rem;
`;

const Divider = styled.div`
  flex-shrink: 0;
  align-self: stretch;
  width: 1px;
  background: ${p => p.theme.colors.bg2};

  @media (max-width: 40rem) {
    width: auto;
    height: 1px;
  }
`;

const Label = styled.span`
  font-size: 0.95rem;
  font-weight: 600;
`;

const Hint = styled.p`
  margin: 0;
  color: ${p => p.theme.colors.textLight};
  font-size: 0.82rem;
`;

/** The QR is a fixed square; centre it rather than letting it hug the edge. */
const Centered = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  min-width: 0;
`;

const Form = styled.form`
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  align-items: center;
`;

const Input = styled.input`
  flex: 1 1 12rem;
  min-width: 0;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  padding: 0.5rem 0.6rem;
  font-size: 0.85rem;
  background: ${p => p.theme.colors.bg};
  color: ${p => p.theme.colors.text};
  box-sizing: border-box;
`;

const Message = styled.p`
  margin: 0;
  color: ${p => p.theme.colors.alert};
  font-size: 0.82rem;
`;

const DocsLink = styled.a`
  font-size: 0.8rem;
  color: ${p => p.theme.colors.textLight};
  align-self: flex-start;
`;
