import React from 'react';
import styled, { DefaultTheme } from 'styled-components';
import { transition } from '../../helpers/transition';

export enum IconButtonVariant {
  Simple,
  Outline,
  Fill,
  Colored,
}

type ColorProp = keyof DefaultTheme['colors'] | 'inherit';

interface BaseProps {
  className?: string;
  variant?: IconButtonVariant;
  color?: ColorProp;
  size?: string;
  title: string;
}

export type IconButtonProps = BaseProps &
  React.ButtonHTMLAttributes<HTMLButtonElement>;

export const IconButton = React.forwardRef<
  HTMLButtonElement,
  React.PropsWithChildren<IconButtonProps>
>(({ variant, children, color, ...props }, ref) => {
  const Comp = ComponentMap.get(variant!) ?? SimpleIconButton;

  return (
    <Comp ref={ref} color={color!} {...props}>
      {children}
    </Comp>
  );
});

IconButton.displayName = 'IconButton';

const defaultProps = {
  variant: IconButtonVariant.Simple,
  color: 'inherit',
  size: '1em',
} as IconButtonProps;

IconButton.defaultProps = defaultProps;

export type IconButtonLinkProps = BaseProps &
  React.AnchorHTMLAttributes<HTMLAnchorElement> & {
    href: string;
  };

export const IconButtonLink = React.forwardRef<
  HTMLAnchorElement,
  React.PropsWithChildren<IconButtonLinkProps>
>(({ variant, children, color, ...props }, ref) => {
  const Comp = ComponentMap.get(variant!) ?? SimpleIconButton;

  return (
    <Comp ref={ref} color={color!} as='a' {...props}>
      {children}
    </Comp>
  );
});

IconButtonLink.displayName = 'IconButtonLink';

IconButtonLink.defaultProps = defaultProps as IconButtonLinkProps;

interface BaseProps {
  size?: string;
}

const IconButtonBase = styled.button<BaseProps>`
  --button-padding: 0.4em;
  cursor: pointer;
  display: inline-grid;
  place-items: center;
  ${transition('background-color', 'color', 'box-shadow', 'filter')};
  color: ${p => p.theme.colors.text};
  font-size: ${p => p.size ?? '1em'};
  border: none;

  padding: var(--button-padding);
  width: calc(1em + var(--button-padding) * 2);
  height: calc(1em + var(--button-padding) * 2);

  &[disabled] {
    opacity: 0.5;
    cursor: not-allowed;
  }
`;

interface ButtonStyleProps {
  color: ColorProp;
}

const SimpleIconButton = styled(IconButtonBase)<ButtonStyleProps>`
  color: ${p => (p.color === 'inherit' ? 'inherit' : p.theme.colors[p.color])};
  background-color: transparent;
  border-radius: ${p => p.theme.radius};

  &:not([disabled]) {
    &:hover,
    &:focus {
      background-color: ${p => p.theme.colors.bg1};
    }

    :active {
      background-color: ${p => p.theme.colors.bg2};
    }
  }
`;

const OutlineIconButton = styled(IconButtonBase)<ButtonStyleProps>`
  color: ${p => (p.color === 'inherit' ? 'inherit' : p.theme.colors[p.color])};
  background-color: ${p => p.theme.colors.bg};
  border-radius: 50%;

  &:not([disabled]) {
    &:hover,
    &:focus {
      color: ${p => p.theme.colors.main};
      box-shadow: 0px 0px 0px 1.5px ${p => p.theme.colors.main},
        ${p => p.theme.boxShadowSoft};
    }
  }

  &&:active {
    background-color: ${p => p.theme.colors.main};
    color: white;
  }
`;

const FillIconButton = styled(IconButtonBase)<ButtonStyleProps>`
  color: ${p => (p.color === 'inherit' ? 'inherit' : p.theme.colors[p.color])};
  background-color: unset;
  border-radius: 50%;
  &:hover,
  &:focus {
    color: white;
    background-color: ${p => p.theme.colors.main};
    box-shadow: ${p => p.theme.boxShadowSoft};
  }
`;

const ColoredIconButton = styled(IconButtonBase)<ButtonStyleProps>`
  color: white;
  background-color: ${p =>
    p.color === 'inherit' ? 'inherit' : p.theme.colors[p.color]};
  border-radius: 50%;
  &:hover,
  &:focus {
    color: white;
    filter: brightness(1.3);
    box-shadow: ${p => p.theme.boxShadowSoft};
  }
`;

const ComponentMap = new Map([
  [IconButtonVariant.Simple, SimpleIconButton],
  [IconButtonVariant.Outline, OutlineIconButton],
  [IconButtonVariant.Fill, FillIconButton],
  [IconButtonVariant.Colored, ColoredIconButton],
]);
