import { useRef, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { FaMagnifyingGlass, FaXmark } from 'react-icons/fa6';
import { IconButton } from '@components/IconButton/IconButton';

interface QuickFilterFieldProps {
  value: string;
  onChange: (value: string) => void;
}

/** Below this width the field folds into its icon until you open it. */
const COLLAPSE_BELOW = '40rem';

/**
 * The table toolbar's quick filter: type, and only the rows that show that text
 * in some column stay. Not a search of the drive — that is the header's Search.
 *
 * ✕ or Escape clears it. On a phone it takes the room of one icon until opened,
 * and folds back when it is left empty.
 */
export function QuickFilterField({
  value,
  onChange,
}: QuickFilterFieldProps): JSX.Element {
  const inputRef = useRef<HTMLInputElement>(null);
  const [opened, setOpened] = useState(false);
  // Something typed keeps it open: hiding a filter that is narrowing the rows
  // would leave you wondering where they went.
  const expanded = opened || value !== '';

  const open = () => {
    setOpened(true);
    // The input is only laid out once it is expanded.
    requestAnimationFrame(() => inputRef.current?.focus());
  };

  const clear = () => {
    onChange('');
    inputRef.current?.focus();
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key !== 'Escape') {
      return;
    }

    // Escape belongs to the field here, not to a dialog or the grid behind it.
    e.stopPropagation();

    if (value !== '') {
      onChange('');
    } else {
      setOpened(false);
      inputRef.current?.blur();
    }
  };

  return (
    <Wrapper data-expanded={expanded} role='search'>
      <OpenButton
        type='button'
        title='Find rows'
        aria-expanded={expanded}
        onClick={open}
      >
        <FaMagnifyingGlass />
      </OpenButton>
      <Field>
        <FaMagnifyingGlass aria-hidden />
        <Input
          ref={inputRef}
          type='text'
          value={value}
          placeholder='Find rows…'
          aria-label='Find rows containing text'
          onChange={e => onChange(e.target.value)}
          onKeyDown={handleKeyDown}
          onFocus={() => setOpened(true)}
          onBlur={() => setOpened(false)}
        />
        {value !== '' && (
          <IconButton
            type='button'
            title='Clear'
            onClick={clear}
            // Keep focus in the field, so clearing doesn't fold it away.
            onMouseDown={e => e.preventDefault()}
          >
            <FaXmark />
          </IconButton>
        )}
      </Field>
    </Wrapper>
  );
}

const Wrapper = styled.div`
  display: flex;
  align-items: center;
  min-width: 0;
`;

const OpenButton = styled.button`
  display: none;
  align-items: center;
  justify-content: center;
  height: 1.85rem;
  width: 1.85rem;
  border: none;
  border-radius: ${p => p.theme.radius};
  background-color: transparent;
  color: ${p => p.theme.colors.textLight};
  cursor: pointer;

  &:hover,
  &:focus-visible {
    background-color: ${p => p.theme.colors.bg1};
    color: ${p => p.theme.colors.text};
  }

  @media (max-width: ${COLLAPSE_BELOW}) {
    ${Wrapper}[data-expanded='false'] & {
      display: inline-flex;
    }
  }
`;

const Field = styled.div`
  display: flex;
  align-items: center;
  gap: 0.35rem;
  height: 1.85rem;
  width: 13rem;
  padding-inline: 0.5rem 0.25rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  background-color: ${p => p.theme.colors.bg};

  & > svg {
    flex-shrink: 0;
    color: ${p => p.theme.colors.textLight};
    font-size: 0.85em;
  }

  &:focus-within {
    border-color: ${p => p.theme.colors.main};
  }

  @media (max-width: ${COLLAPSE_BELOW}) {
    width: 10rem;

    ${Wrapper}[data-expanded='false'] & {
      display: none;
    }
  }
`;

const Input = styled.input`
  flex: 1;
  min-width: 0;
  height: 100%;
  border: none;
  outline: none;
  padding: 0;
  font-size: 0.9em;
  color: ${p => p.theme.colors.text};
  background: transparent;
`;
