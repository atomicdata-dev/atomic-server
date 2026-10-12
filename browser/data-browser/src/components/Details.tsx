import {
  PropsWithChildren,
  useCallback,
  useEffect,
  useState,
  type JSX,
  type ReactNode,
} from 'react';
import { styled, css } from 'styled-components';
import { FaCaretRight } from 'react-icons/fa6';
import { Collapse } from './Collapse';
import { IconButton } from './IconButton/IconButton';

export type DetailsPropsBase = {
  open?: boolean;
  initialState?: boolean;
  disabled?: boolean;
  /** Event that fires when a user opens or closes the details */
  onStateToggle?: (state: boolean) => void;
  noIndent?: boolean;
  /**
   * When false, clicking the summary row does not toggle (caret still does).
   * Use when the title contains other controls. Default true. Title mode only.
   */
  summaryClickable?: boolean;
  /**
   * When false, no leading caret in the summary (e.g. resource sidebar puts expand
   * affordance in the title row’s icon slot). Default true. Title mode only.
   */
  showCaret?: boolean;
  subtle?: boolean;
};

type DetailsPropsWithTitle = DetailsPropsBase & {
  title: ReactNode;
  titleButton?: never;
};

type DetailsPropsWithTitleButton = DetailsPropsBase & {
  /** Label that toggles open/closed; omit the caret row. */
  titleButton: ReactNode;
  title?: never;
};

export type DetailsProps = DetailsPropsWithTitle | DetailsPropsWithTitleButton;

/** A collapsible item with a title. Similar to the <details> HTML element. */
export function Details(props: PropsWithChildren<DetailsProps>): JSX.Element {
  const {
    open = false,
    subtle = false,
    initialState,
    children,
    disabled,
    noIndent,
    onStateToggle,
    summaryClickable = true,
    showCaret = true,
  } = props;
  const [isOpen, setIsOpen] = useState(initialState);

  useEffect(() => {
    setIsOpen(open);
  }, [open]);

  useEffect(() => {
    setIsOpen(initialState);
  }, [initialState]);

  const toggleOpen = useCallback(() => {
    // Not inside the state updater: it must stay pure, and a parent's
    // `setState` from there is a state update during render.
    const next = !isOpen;
    setIsOpen(next);
    onStateToggle?.(next);
  }, [isOpen, onStateToggle]);

  // titleButton renders its own <button>; wrapper onClick would double-toggle on click.
  const summaryRowClickToggle =
    'title' in props && showCaret && summaryClickable && !disabled
      ? toggleOpen
      : undefined;
  const summaryRowIsClickable = summaryRowClickToggle !== undefined;

  return (
    <>
      <SummaryWrapper
        onClick={summaryRowClickToggle}
        $clickable={summaryRowIsClickable}
      >
        {'titleButton' in props ? (
          <TitleAsButton
            type='button'
            $subtle={subtle}
            onClick={toggleOpen}
            disabled={!!disabled}
            aria-expanded={isOpen}
          >
            {props.titleButton}
          </TitleAsButton>
        ) : (
          <>
            {showCaret ? (
              <StyledIconButton
                type='button'
                title={isOpen ? 'collapse' : 'expand'}
                onClick={e => {
                  e.stopPropagation();
                  toggleOpen();
                }}
                hide={!!disabled}
                aria-label={isOpen ? 'collapse' : 'expand'}
              >
                <Icon $turn={!!isOpen} $subtle={subtle} />
              </StyledIconButton>
            ) : null}
            <TitleWrapper $noLeadingCaret={!showCaret}>
              {'title' in props ? props.title : null}
            </TitleWrapper>
          </>
        )}
      </SummaryWrapper>
      <StyledCollapse open={!!isOpen} noIndent={noIndent}>
        {children}
      </StyledCollapse>
    </>
  );
}

const SummaryWrapper = styled.div<{ $clickable: boolean }>`
  box-sizing: border-box;
  width: 100%;
  max-width: 100%;
  display: flex;
  align-items: center;
  gap: 0.4rem;
  border-radius: ${p => p.theme.radius};
  user-select: none;
  transition: background-color ${p => p.theme.animation.duration} ease-out;

  cursor: ${p => (p.$clickable ? 'pointer' : 'default')};

  ${p =>
    p.$clickable
      ? css`
          /* Match {@link SideBarItem} padding + hover affordance */
          padding: 0.2rem;

          &:hover,
          &:focus-within {
            background-color: ${p.theme.colors.bg1};
          }

          &:active {
            background-color: ${p.theme.colors.bg2};
          }
        `
      : ''}
`;

const TitleWrapper = styled.div<{ $noLeadingCaret: boolean }>`
  flex: 1;
  min-width: 0;
  max-width: 100%;
  ${p =>
    p.$noLeadingCaret
      ? ''
      : `
    width: 1px;
  `}
  * {
    user-select: none;
  }
`;

const TitleAsButton = styled.button<{ $subtle: boolean }>`
  flex: 1;
  width: 1px;
  text-align: left;
  border: none;
  background: transparent;
  padding: 0;
  margin: 0;
  font: inherit;
  color: ${({ theme, $subtle }) =>
    $subtle ? theme.colors.textLight : 'inherit'};
  cursor: pointer;
  display: flex;
  align-items: center;
  min-width: 0;

  &:disabled {
    cursor: default;
    opacity: 0.6;
  }

  * {
    user-select: none;
    cursor: inherit;
  }
`;

const Icon = styled(FaCaretRight)<{ $turn: boolean; $subtle: boolean }>`
  color: ${({ theme, $subtle }) =>
    $subtle ? theme.colors.textLight : theme.colors.main};
  margin-top: auto;
  cursor: pointer;
  * {
    cursor: pointer;
  }
  --speed: ${p => p.theme.animation.duration};
  transition:
    transform var(--speed) ease-in-out,
    background-color var(--speed) ease;
  transform: rotate(${props => (props.$turn ? '90deg' : '0deg')});
  aspect-ratio: 1/1;
  display: flex;
  align-items: center;
`;

const StyledIconButton = styled(IconButton)<{ hide: boolean }>`
  font-size: 1rem;
  margin-right: -0.3rem;
  visibility: ${props => (props.hide ? 'hidden' : 'visible')};
`;

const StyledCollapse = styled(Collapse)<{ noIndent?: boolean }>`
  margin-left: ${p => (p.noIndent ? 0 : p.theme.margin) + 'rem'};
`;
