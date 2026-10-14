import {
  ComponentType,
  ButtonHTMLAttributes,
  AnchorHTMLAttributes,
} from 'react';
import { styled, DefaultTheme, keyframes } from 'styled-components';
import { transition } from '../../helpers/transition';
import { adjustHue } from 'polished';

export enum IconButtonVariant {
  Simple,
  Outline,
  Fill,
  Colored,
  Square,
  Magic,
}

type ColorProp = keyof DefaultTheme['colors'] | 'inherit';

type BaseProps = {
  className?: string;
  variant?: IconButtonVariant;
  color?: ColorProp;
  size?: string;
  title: string;
  edgeAlign?: 'start' | 'end';
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  as?: string | ComponentType<any>;
};

export type IconButtonProps = BaseProps &
  ButtonHTMLAttributes<HTMLButtonElement> & {
    ref?: React.Ref<HTMLButtonElement | null>;
  };

export const IconButton: React.FC<React.PropsWithChildren<IconButtonProps>> = ({
  variant = IconButtonVariant.Simple,
  color = 'inherit',
  size = '1em',
  children,
  ref,
  ...props
}) => {
  const Comp = ComponentMap.get(variant!) ?? SimpleIconButton;

  return (
    <Comp ref={ref} color={color} size={size} {...props}>
      {children}
    </Comp>
  );
};

export type IconButtonLinkProps = BaseProps &
  AnchorHTMLAttributes<HTMLAnchorElement> & {
    href: string;
    ref?: React.Ref<HTMLAnchorElement | null>;
  };

export const IconButtonLink: React.FC<
  React.PropsWithChildren<IconButtonLinkProps>
> = ({
  variant = IconButtonVariant.Simple,
  color = 'inherit',
  size = '1em',
  ref,
  children,
  ...props
}) => {
  const Comp = ComponentMap.get(variant ?? IconButtonVariant.Simple)!;

  return (
    <Comp ref={ref} color={color!} size={size} as='a' {...props}>
      {children}
    </Comp>
  );
};

interface ButtonBaseProps {
  size?: string;
  edgeAlign?: 'start' | 'end';
}

const IconButtonBase = styled.button<ButtonBaseProps>`
  --button-padding: 0.4em;
  cursor: pointer;
  display: inline-grid;
  place-items: center;
  ${transition('background-color', 'color', 'box-shadow', 'filter')};
  color: ${p => p.theme.colors.text};
  font-size: ${p => p.size ?? '1em'};
  border: none;
  user-select: none;
  padding: var(--button-padding);
  aspect-ratio: 1/1;
  height: 2em;
  margin-inline-start: ${p =>
    p.edgeAlign === 'start' ? 'calc(var(--button-padding) * -1)' : '0'};

  margin-inline-end: ${p =>
    p.edgeAlign === 'end' ? 'calc(var(--button-padding) * -1)' : '0'};
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
    &:focus-visible {
      background-color: ${p => p.theme.colors.bg1};
    }
    /* Touch keeps :hover after a tap; only apply it with a real hover. */
    @media (hover: hover) {
      &:hover {
        background-color: ${p => p.theme.colors.bg1};
      }
    }

    &:active {
      background-color: ${p => p.theme.colors.bg2};
    }
  }
`;

const OutlineIconButton = styled(IconButtonBase)<ButtonStyleProps>`
  color: ${p => (p.color === 'inherit' ? 'inherit' : p.theme.colors[p.color])};
  background-color: ${p => p.theme.colors.bg};
  border-radius: 50%;

  &:not([disabled]) {
    &:focus-visible {
      color: ${p => p.theme.colors.main};
      box-shadow:
        0px 0px 0px 1.5px ${p => p.theme.colors.main},
        ${p => p.theme.boxShadowSoft};
    }
    /* Touch keeps :hover after a tap; only apply it with a real hover. */
    @media (hover: hover) {
      &:hover {
        color: ${p => p.theme.colors.main};
        box-shadow:
          0px 0px 0px 1.5px ${p => p.theme.colors.main},
          ${p => p.theme.boxShadowSoft};
      }
    }
  }

  &&:active {
    background-color: ${p => p.theme.colors.main};
    color: white;
  }
`;

const SquareIconButton = styled(IconButtonBase)<ButtonStyleProps>`
  color: ${p => (p.color === 'inherit' ? 'inherit' : p.theme.colors[p.color])};
  background-color: ${p => p.theme.colors.bg};
  border-radius: ${p => p.theme.radius};
  border: 1px solid ${p => p.theme.colors.bg2};

  &:not([disabled]) {
    &:focus-visible {
      color: ${p => p.theme.colors.main};
      border-color: ${p => p.theme.colors.main};
      box-shadow: ${p => p.theme.boxShadowSoft};
    }
    /* Touch keeps :hover after a tap; only apply it with a real hover. */
    @media (hover: hover) {
      &:hover {
        color: ${p => p.theme.colors.main};
        border-color: ${p => p.theme.colors.main};
        box-shadow: ${p => p.theme.boxShadowSoft};
      }
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
  &:focus-visible {
    color: white;
    background-color: ${p => p.theme.colors.main};
    box-shadow: ${p => p.theme.boxShadowSoft};
  }
  /* Touch keeps :hover after a tap; only apply it with a real hover. */
  @media (hover: hover) {
    &:hover {
      color: white;
      background-color: ${p => p.theme.colors.main};
      box-shadow: ${p => p.theme.boxShadowSoft};
    }
  }
`;

const ColoredIconButton = styled(IconButtonBase)<ButtonStyleProps>`
  color: white;
  background-color: ${p =>
    p.color === 'inherit' ? 'inherit' : p.theme.colors[p.color]};
  border-radius: 50%;
  &:focus-visible {
    color: white;
    filter: brightness(1.3);
    box-shadow: ${p => p.theme.boxShadowSoft};
  }
  /* Touch keeps :hover after a tap; only apply it with a real hover. */
  @media (hover: hover) {
    &:hover {
      color: white;
      filter: brightness(1.3);
      box-shadow: ${p => p.theme.boxShadowSoft};
    }
  }
`;

const cycle = keyframes`
  from {
    filter: hue-rotate(0deg) brightness(var(--brightness-factor)) saturate(1.5);
  }
  to {
    filter: hue-rotate(360deg) brightness(var(--brightness-factor)) saturate(2);
  }
`;

const MagicIconButton = styled(IconButtonBase)<ButtonStyleProps>`
  --border-width: 2px;
  --brightness-factor: ${p => (p.theme.darkMode ? 1 : 1.5)};
  --bg-opacity: ${p => (p.theme.darkMode ? 0.5 : 0.8)};
  background: transparent;
  position: relative;
  color: inherit;
  aspect-ratio: 1/1;
  ${transition('color', 'background')}

  &::before,
  &::after {
    aspect-ratio: 1/1;
    content: '';
    position: absolute;
    transform: scale(0);
    ${transition('opacity', 'transform')}
  }

  &::before {
    border-radius: ${p => p.theme.radius};
    inset: 0;
    opacity: 0;
    z-index: -2;
    will-change: filter;
    background:
      radial-gradient(ellipse at top right, #365ccd, transparent),
      radial-gradient(
        ellipse at bottom left,
        ${adjustHue(-45, '#365ccd')},
        transparent
      ),
      radial-gradient(
        ellipse at bottom right,
        ${adjustHue(180, '#365ccd')},
        transparent
      );
  }
  &::after {
    content: '';
    aspect-ratio: 1/1;
    backdrop-filter: blur(9px);
    position: absolute;
    inset: var(--border-width);
    opacity: var(--bg-opacity);
    will-change: transform;
    border-radius: calc(${p => p.theme.radius} - var(--border-width));
    background: ${p => p.theme.colors.bg};
    z-index: -1;
  }

  &:focus-visible {
    color: ${p => p.theme.colors.text};
    &::before,
    &::after {
      transform: scale(1);
    }
    &::before {
      opacity: 1;
      animation: ${cycle} 3s linear infinite;
    }
  }
  /* Touch keeps :hover after a tap; only apply it with a real hover. */
  @media (hover: hover) {
    &:hover {
      color: ${p => p.theme.colors.text};
      &::before,
      &::after {
        transform: scale(1);
      }
      &::before {
        opacity: 1;
        animation: ${cycle} 3s linear infinite;
      }
    }
  }

  &:active {
    filter: brightness(0.8);
  }
`;

const ComponentMap = new Map([
  [IconButtonVariant.Simple, SimpleIconButton],
  [IconButtonVariant.Outline, OutlineIconButton],
  [IconButtonVariant.Fill, FillIconButton],
  [IconButtonVariant.Colored, ColoredIconButton],
  [IconButtonVariant.Square, SquareIconButton],
  [IconButtonVariant.Magic, MagicIconButton],
]);
