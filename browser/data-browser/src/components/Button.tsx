import { forwardRef, PropsWithChildren } from 'react';
import { styled } from 'styled-components';
import { transition } from '../helpers/transition';
import { Spinner } from './Spinner';

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  /** Description of the button, required if the button only has an icon */
  name?: string;
  /** Renders the button less clicky */
  subtle?: boolean;
  alert?: boolean;
  /** If it's just an icon */
  icon?: boolean;
  /** Minimal styling */
  clean?: boolean;
  /** Shows loading text + a spinner */
  loading?: string;
  /** Add a bottom margin */
  gutter?: boolean;
  onClick?: (e: React.MouseEvent) => unknown;
  className?: string;
  as?: keyof HTMLElementTagNameMap;
}

interface ButtonPropsStyled {
  gutter?: boolean;
}

const getButtonComp = ({ clean, icon, subtle, alert }: ButtonProps) => {
  let Comp = ButtonDefault;

  if (subtle) {
    Comp = ButtonSubtle;
  }

  if (alert) {
    Comp = ButtonAlert;
  }

  if (icon) {
    Comp = ButtonIcon;
  }

  if (clean) {
    // @ts-ignore
    Comp = ButtonClean;
  }

  return Comp;
};

export const Button = forwardRef<
  HTMLButtonElement,
  PropsWithChildren<ButtonProps>
>(({ children, loading, ...props }, ref): JSX.Element => {
  // Filter out props that should not be passed to the button element or styled component.
  const { icon: _icon, ...buttonProps } = props;

  const Comp = getButtonComp(props);

  return (
    <Comp type='button' {...buttonProps} ref={ref}>
      {loading ? <Spinner /> : children}
    </Comp>
  );
});

Button.displayName = 'Button';

/** Extremly minimal set of button properties */
export const ButtonClean = styled.button<ButtonPropsStyled>`
  cursor: pointer;
  border: none;
  font-size: inherit;
  padding: 0;
  color: inherit;
  margin: 0;
  appearance: none;
  background-color: initial;
  -webkit-tap-highlight-color: transparent; /* Remove the tap / click effect on touch devices */
  user-select: none;
`;

/** Base button style. You're likely to want to use ButtonMargin in most places */
export const ButtonBase = styled(ButtonClean)`
  height: 2rem;
  display: flex;
  align-items: center;
  gap: 1ch;
  justify-content: center;
  background-color: ${props => props.theme.colors.main};
  color: ${props => props.theme.colors.bg};
  white-space: nowrap;
  margin-bottom: ${p => (p.gutter ? `${p.theme.margin}rem` : '')};
  ${transition(
    'background-color',
    'box-shadow',
    'transform',
    'color',
    'border-color',
  )};

  // Prevent sticky hover buttons on touch devices
  @media (hover: hover) and (pointer: fine) {
    &:hover:not([disabled]),
    &:focus-visible:not([disabled]) {
      border-color: ${props => props.theme.colors.main};
      outline: 0;
    }
  }

  &:active:not([disabled]) {
    transition: all 0s;
    /* background-color: ${props => props.theme.colors.mainDark}; */
    /* color: ${props => props.theme.colors.bg}; */
  }

  &:disabled {
    cursor: default;
    display: auto;
    opacity: 0.5;
  }
`;

interface ButtonBarProps {
  leftPadding?: boolean;
  rightPadding?: boolean;
  selected?: boolean;
}

/** Button inside the navigation bar */
// eslint-disable-next-line prettier/prettier
export const ButtonBar = styled(ButtonClean)<ButtonBarProps>`
  padding-right: 0.5rem;
  padding-left: 0.5rem;
  color: ${p => p.theme.colors.main};
  background-color: ${p =>
    p.selected ? p.theme.colors.bg2 : p.theme.colors.bg};
  height: 100%;
  display: flex;
  align-items: center;

  &:hover:not([disabled]),
  /* &:active:not([disabled]), */
  &:focus-visible:not([disabled]) {
    background-color: ${p => p.theme.colors.bg1};
  }

  &:active:not([disabled]) {
    background-color: ${p => p.theme.colors.bg2};
  }

  padding-left: ${p => (p.leftPadding ? '1.2rem' : '')};
  padding-right: ${p => (p.rightPadding ? '1.2rem' : '')};
`;

/** Button with some optional margins around it */
// eslint-disable-next-line prettier/prettier
export const ButtonDefault = styled(ButtonBase)<ButtonPropsStyled>`
  --button-bg-color: ${p => p.theme.colors.main};
  --button-bg-color-hover: ${p => p.theme.colors.mainLight};
  --button-border-color: ${p => p.theme.colors.main};
  --button-border-color-hover: ${p => p.theme.colors.mainLight};
  --button-text-color: ${p => p.theme.colors.bg};
  --button-text-color-hover: ${p => p.theme.colors.bg};

  padding: 0.4rem;
  border-radius: ${p => p.theme.radius};
  padding-left: ${p => p.theme.margin}rem;
  padding-right: ${p => p.theme.margin}rem;
  display: inline-flex;
  background-color: var(--button-bg-color);
  color: var(--button-text-color);
  border: solid 1px var(--button-border-color);

  &:focus-visible:not([disabled]),
  &:hover:not([disabled]) {
    box-shadow: ${p => p.theme.boxShadowSoft};
    background-color: var(--button-bg-color-hover);
    color: var(--button-text-color-hover);
    border-color: var(--button-border-color-hover);
  }

  &:active:not([disabled]) {
    box-shadow: inset ${p => p.theme.boxShadowIntense};
  }
`;

export const ButtonSubtle = styled(ButtonDefault)`
  --button-bg-color: ${p => p.theme.colors.bg};
  --button-bg-color-hover: ${p => p.theme.colors.bg};
  --button-border-color: ${p => p.theme.colors.bg2};
  --button-border-color-hover: ${p => p.theme.colors.main};
  --button-text-color: ${p => p.theme.colors.textLight};
  --button-text-color-hover: ${p => p.theme.colors.main};

  box-shadow: ${p => p.theme.boxShadow};
`;

export const ButtonAlert = styled(ButtonDefault)`
  --button-bg-color: ${p => p.theme.colors.alert};
  --button-bg-color-hover: ${p => p.theme.colors.alertLight};
  --button-border-color: ${p => p.theme.colors.alert};
  --button-border-color-hover: ${p => p.theme.colors.alertLight};
`;

/** Button that only shows an icon */
export const ButtonIcon = styled(ButtonDefault)`
  box-shadow: none;
  border-color: transparent;
  border-radius: 999px;
  font-size: 0.8rem;
  width: 1.3rem;
  height: 1.3rem;
  display: inline-flex;
  margin: 0;
  padding: 0;

  &:active:not([disabled]) {
    box-shadow: ${props => props.theme.boxShadowIntense};
  }

  &:active:not([disabled]) {
    box-shadow: inset ${props => props.theme.boxShadowIntense};
  }
`;

/** A button inside an input field */
export const ButtonInput = styled(ButtonBase)`
  padding: 0 0.5rem;
  background-color: ${props => props.theme.colors.bg};
  color: ${props => props.theme.colors.textLight};
  flex: 0;
  height: auto;
  border-left: solid 1px ${props => props.theme.colors.bg2};
  border-radius: 0;

  /** Prevent sticky hover buttons on touch devices */
  @media (hover: hover) and (pointer: fine) {
    &:hover:not([disabled]),
    &:active:not([disabled]),
    &:focus-visible:not([disabled]) {
      color: ${props => props.theme.colors.main};
      background-color: ${props => props.theme.colors.bg1};
    }
  }

  &:last-child {
    border-radius: ${props => props.theme.radius};
    border-top-left-radius: 0;
    border-bottom-left-radius: 0;
  }
`;
