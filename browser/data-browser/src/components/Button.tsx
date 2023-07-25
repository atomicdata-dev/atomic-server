import React from 'react';
import styled from 'styled-components';
import { transition } from '../helpers/transition';
import { Spinner } from './Spinner';

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  /** Description of the button, required if the button only has an icon */
  name?: string;
  /** Renders the button less clicky */
  subtle?: boolean;
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
}

export const Button = React.forwardRef<
  HTMLButtonElement,
  React.PropsWithChildren<ButtonProps>
>(({ children, clean, icon, loading, ...props }, ref): JSX.Element => {
  let Comp = ButtonDefault;

  if (icon) {
    Comp = ButtonIcon;
  }

  if (clean) {
    //@ts-ignore
    Comp = ButtonClean;
  }

  return (
    <Comp type='button' {...props} ref={ref}>
      {loading ? <Spinner /> : children}
    </Comp>
  );
});

Button.displayName = 'Button';

/** Extremly minimal set of button properties */
export const ButtonClean = styled.button<ButtonProps>`
  cursor: pointer;
  border: none;
  outline: none;
  font-size: inherit;
  padding: 0;
  color: inherit;
  margin: 0;
  -webkit-appearance: none;
  background-color: initial;
  -webkit-tap-highlight-color: transparent; /* Remove the tap / click effect on touch devices */
`;

/** Base button style. You're likely to want to use ButtonMargin in most places */
export const ButtonBase = styled(ButtonClean)`
  height: 2rem;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: ${props => props.theme.colors.main};
  color: ${props => props.theme.colors.bg};
  white-space: nowrap;
  margin-bottom: ${p => (p.gutter ? `${p.theme.margin}rem` : '')};
  ${transition('background-color', 'box-shadow', 'transform', 'color')};

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
export const ButtonDefault = styled(ButtonBase)<ButtonProps>`
  padding: 0.4rem;
  border-radius: ${p => p.theme.radius};
  padding-left: ${p => p.theme.margin}rem;
  padding-right: ${p => p.theme.margin}rem;
  box-shadow: ${p => (p.subtle ? p.theme.boxShadow : 'none')};
  display: inline-flex;
  background-color: ${p =>
    p.subtle ? p.theme.colors.bg : p.theme.colors.main};
  color: ${p => (p.subtle ? p.theme.colors.textLight : p.theme.colors.bg)};
  border: solid 1px
    ${p => (p.subtle ? p.theme.colors.bg2 : p.theme.colors.main)};

  &:focus-visible:not([disabled]),
  &:hover:not([disabled]) {
    box-shadow: ${p => p.theme.boxShadowSoft};
    background-color: ${p =>
      p.subtle ? p.theme.colors.bg : p.theme.colors.mainLight};
    color: ${p => (p.subtle ? p.theme.colors.main : p.theme.colors.bg)};
    border-color: ${p =>
      p.subtle ? p.theme.colors.main : p.theme.colors.mainLight};
  }

  &:active:not([disabled]) {
    box-shadow: inset ${p => p.theme.boxShadowIntense};
  }
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
