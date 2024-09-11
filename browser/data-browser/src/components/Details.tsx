import { PropsWithChildren, useCallback, useEffect, useState } from 'react';
import { styled } from 'styled-components';
import { FaCaretRight } from 'react-icons/fa';
import { Collapse } from './Collapse';

export interface DetailsProps {
  open?: boolean;
  initialState?: boolean;
  title: React.ReactElement | string;
  disabled?: boolean;
  /** Event that fires when a user opens or closes the details */
  onStateToggle?: (state: boolean) => void;
  noIndent?: boolean;
}

/** A collapsible item with a title. Similar to the <details> HTML element. */
export function Details({
  open = false,
  initialState,
  children,
  title,
  disabled,
  noIndent,
  onStateToggle,
}: PropsWithChildren<DetailsProps>): JSX.Element {
  const [isOpen, setIsOpen] = useState(initialState);

  useEffect(() => {
    setIsOpen(open);
  }, [open]);

  useEffect(() => {
    setIsOpen(initialState);
  }, [initialState]);

  const toggleOpen = useCallback(() => {
    setIsOpen(p => {
      onStateToggle?.(!p);

      return !p;
    });
  }, []);

  return (
    <>
      <SummaryWrapper>
        <IconButton
          type='button'
          onClick={toggleOpen}
          turn={!!isOpen}
          hide={!!disabled}
          aria-label={isOpen ? 'collapse' : 'expand'}
        >
          <Icon />
        </IconButton>
        <TitleWrapper>{title}</TitleWrapper>
      </SummaryWrapper>
      <StyledCollapse open={!!isOpen} noIndent={noIndent}>
        {children}
      </StyledCollapse>
    </>
  );
}

const SummaryWrapper = styled.div`
  max-width: 100%;
  display: flex;
  align-items: center;
  gap: 0.4rem;
`;

const TitleWrapper = styled.div`
  flex: 1;
  width: 1px;
  * {
    user-select: none;
  }
`;

interface IconButtonProps {
  turn: boolean;
  hide: boolean;
}

const Icon = styled(FaCaretRight)`
  color: ${({ theme }) => theme.colors.main};
  margin-top: auto;
  cursor: pointer;
  * {
    cursor: pointer;
  }
  font-size: 1.2rem;
`;

const IconButton = styled.button<IconButtonProps>`
  --speed: ${p => p.theme.animation.duration};
  aspect-ratio: 1/1;
  display: flex;
  align-items: center;
  padding: 0.2rem;
  visibility: ${props => (props.hide ? 'hidden' : 'visible')};
  transition:
    transform var(--speed) ease-in-out,
    background-color var(--speed) ease;
  transform: rotate(${props => (props.turn ? '90deg' : '0deg')});
  background-color: transparent;
  border: none;
  border-radius: 50%;
  &:hover,
  &:focus {
    background-color: ${p => p.theme.colors.bg1};
  }
`;

const StyledCollapse = styled(Collapse)<{ noIndent?: boolean }>`
  overflow-x: hidden;
  margin-left: ${p => (p.noIndent ? 0 : p.theme.margin) + 'rem'};
`;
