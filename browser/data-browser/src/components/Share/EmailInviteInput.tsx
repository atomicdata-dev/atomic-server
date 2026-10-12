import { useRef, type JSX } from 'react';
import { styled } from 'styled-components';
import { FaXmark } from 'react-icons/fa6';
import { RoleSwitch, type ShareRole } from './RoleSelect';

/** Loose on purpose: the server decides, this only catches typos early. */
export const isEmailAddress = (value: string): boolean =>
  /^[^\s@,;<>]+@[^\s@,;<>]+\.[^\s@,;<>]+$/.test(value);

const SEPARATORS = /[\s,;]+/;

interface EmailInviteInputProps {
  emails: string[];
  onEmailsChange: (emails: string[]) => void;
  draft: string;
  onDraftChange: (draft: string) => void;
  role: ShareRole;
  onRoleChange: (role: ShareRole) => void;
  disabled?: boolean;
}

/**
 * Email field that turns every typed address into a removable chip. Enter,
 * comma, space and leaving the field all commit what was typed; Backspace in
 * an empty field takes the last chip back. Pasting a list works too.
 */
export function EmailInviteInput({
  emails,
  onEmailsChange,
  draft,
  onDraftChange,
  role,
  onRoleChange,
  disabled,
}: EmailInviteInputProps): JSX.Element {
  const inputRef = useRef<HTMLInputElement>(null);

  /** Moves every complete address out of `text`, and returns what is left. */
  const commit = (text: string, keepLast: boolean): string => {
    const parts = text.split(SEPARATORS);
    const rest = keepLast ? (parts.pop() ?? '') : '';
    const next = [...emails];

    for (const part of parts) {
      const email = part.trim().toLowerCase();

      if (!email) continue;

      if (!isEmailAddress(email)) {
        // Leave anything that is not an address in the field to be fixed.
        return [part, rest].filter(Boolean).join(' ');
      }

      if (!next.includes(email)) next.push(email);
    }

    if (next.length !== emails.length) onEmailsChange(next);

    return rest;
  };

  const handleChange = (value: string) => {
    onDraftChange(SEPARATORS.test(value) ? commit(value, true) : value);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && draft.trim()) {
      e.preventDefault();
      onDraftChange(commit(draft, false));
    } else if (e.key === 'Backspace' && draft === '' && emails.length > 0) {
      e.preventDefault();
      onDraftChange(emails[emails.length - 1]);
      onEmailsChange(emails.slice(0, -1));
    }
  };

  const remove = (email: string) => {
    onEmailsChange(emails.filter(e => e !== email));
    inputRef.current?.focus();
  };

  /**
   * Clicking the empty part of the field focuses the input, like a textbox.
   * Clicks on the controls inside it (the role switch, the chip buttons, the
   * input itself) are left alone: moving focus away from a native select right
   * after it opened blurs it, which closes its option list again.
   */
  const handleFieldClick = (e: React.MouseEvent<HTMLDivElement>) => {
    if ((e.target as Element).closest('label, button, input')) return;

    inputRef.current?.focus();
  };

  return (
    <Field onClick={handleFieldClick}>
      <Chips>
        {emails.map(email => (
          <Chip key={email}>
            {email}
            <ChipRemove
              type='button'
              aria-label={`Remove ${email}`}
              onClick={e => {
                e.stopPropagation();
                remove(email);
              }}
            >
              <FaXmark />
            </ChipRemove>
          </Chip>
        ))}
        <Input
          ref={inputRef}
          type='email'
          multiple
          // These are other people's addresses, not the user's own, so
          // neither the browser nor a password manager should fill them in.
          autoComplete='off'
          data-bwignore
          data-1p-ignore
          data-lpignore='true'
          data-form-type='other'
          disabled={disabled}
          aria-label='Add people by email'
          placeholder={emails.length === 0 ? 'Add people by email' : undefined}
          value={draft}
          onChange={e => handleChange(e.target.value)}
          onKeyDown={handleKeyDown}
          onBlur={() => draft.trim() && onDraftChange(commit(draft, false))}
          data-test='share-email-input'
        />
      </Chips>
      <RoleSwitch
        value={role}
        onChange={onRoleChange}
        aria-label='Role for invited people'
        disabled={disabled}
      />
    </Field>
  );
}

const Field = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  min-height: 3.2rem;
  padding: 0.4rem 0.4rem 0.4rem 0.6rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg};
  cursor: text;
  transition: border-color 100ms ease-in-out;

  &:hover {
    border-color: ${p => p.theme.colors.textLight2};
  }

  &:focus-within {
    border-color: ${p => p.theme.colors.main};
    box-shadow: 0 0 0 1px ${p => p.theme.colors.main};
  }
`;

const Chips = styled.div`
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.35rem;
  flex: 1;
  min-width: 0;
`;

const Chip = styled.span`
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
  max-width: 100%;
  padding: 0.2rem 0.3rem 0.2rem 0.7rem;
  border-radius: 999px;
  background-color: ${p => p.theme.colors.mainSelectedBg};
  color: ${p => p.theme.colors.mainSelectedFg};
  font-size: 0.95rem;
  overflow-wrap: anywhere;
`;

const ChipRemove = styled.button`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 1.3rem;
  height: 1.3rem;
  padding: 0;
  border: none;
  border-radius: 50%;
  background: none;
  color: inherit;
  cursor: pointer;
  font-size: 0.75rem;

  &:hover,
  &:focus-visible {
    background-color: ${p => p.theme.colors.bg};
  }
`;

const Input = styled.input`
  flex: 1;
  min-width: 8rem;
  height: 2rem;
  padding: 0 0.2rem;
  border: none;
  outline: none;
  background: transparent;
  color: ${p => p.theme.colors.text};
  font: inherit;
  font-size: 1rem;

  &::placeholder {
    color: ${p => p.theme.colors.textLight};
  }
`;
