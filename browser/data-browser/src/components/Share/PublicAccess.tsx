import { useState, type JSX } from 'react';
import { styled } from 'styled-components';
import toast from 'react-hot-toast';
import { useResource, useTitle } from '@tomic/react';
import { FaCheck, FaRegCircle } from 'react-icons/fa6';
import type { ShareRole } from './RoleSelect';
import { SegmentedControl } from './SegmentedControl';

type PublicLevel = 'off' | ShareRole;

interface PublicAccessProps {
  /** Public access set on this resource itself */
  level: PublicLevel;
  /** Public access this resource gets from a parent, if any */
  inherited?: { level: ShareRole; setIn: string };
  classLabel: string;
  onChange?: (level: PublicLevel) => Promise<void>;
}

const OPTIONS: { value: PublicLevel; label: string }[] = [
  { value: 'off', label: 'Off' },
  { value: 'read', label: 'Read' },
  { value: 'write', label: 'Write' },
];

/** Whether anyone, without an account or invite, can open the resource. */
export function PublicAccess({
  level,
  inherited,
  classLabel,
  onChange,
}: PublicAccessProps): JSX.Element {
  const [busy, setBusy] = useState(false);
  const isPublic = level !== 'off' || !!inherited;

  const handleChange = async (next: PublicLevel) => {
    if (!onChange) return;
    setBusy(true);

    try {
      await onChange(next);
    } catch (e) {
      toast.error((e as Error).message);
    }

    setBusy(false);
  };

  return (
    <Card data-test='share-public'>
      <IconCircle $active={isPublic} aria-hidden>
        {isPublic ? <FaCheck /> : <FaRegCircle />}
      </IconCircle>
      <Text>
        <strong>Public</strong>
        <Description
          level={level}
          inherited={inherited}
          classLabel={classLabel}
        />
      </Text>
      <SegmentedControl
        options={OPTIONS}
        value={level}
        onChange={handleChange}
        disabled={!onChange || busy}
        aria-label='Public access'
      />
    </Card>
  );
}

function Description({
  level,
  inherited,
  classLabel,
}: Omit<PublicAccessProps, 'onChange'>): JSX.Element {
  const parent = useResource(inherited?.setIn);
  const [parentTitle] = useTitle(parent);

  if (level === 'write') {
    return <Muted>Anyone can open and edit it without joining</Muted>;
  }

  if (level === 'read') {
    return <Muted>Anyone can open it without joining</Muted>;
  }

  if (inherited) {
    return inherited.level === 'write' ? (
      <Muted>Anyone can edit it through {parentTitle}</Muted>
    ) : (
      <Muted>Anyone can open it through {parentTitle}</Muted>
    );
  }

  return <Muted>This {classLabel.toLowerCase()} is not public</Muted>;
}

const Card = styled.div`
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.9rem;
  padding: 1rem;
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg1};
`;

/** The presence dot's green, a shade darker so the white check stays legible. */
const PUBLIC_GREEN = '#2e9e4c';

const IconCircle = styled.span<{ $active: boolean }>`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 2.6rem;
  height: 2.6rem;
  border-radius: 50%;
  background-color: ${p => (p.$active ? PUBLIC_GREEN : p.theme.colors.bg)};
  color: ${p => (p.$active ? 'white' : p.theme.colors.textLight)};
  font-size: 1.2rem;
  transition:
    background-color 150ms ease-in-out,
    color 150ms ease-in-out;
`;

const Text = styled.div`
  display: flex;
  flex-direction: column;
  flex: 1;
  min-width: 10rem;

  strong {
    font-size: 1.05rem;
    font-weight: 600;
  }
`;

const Muted = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.95rem;
`;
