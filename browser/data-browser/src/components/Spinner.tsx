import { styled } from 'styled-components';

interface SpinnerProps {
  size?: string;
  /** Take the surrounding text colour instead of the theme's. */
  inheritColor?: boolean;
  /** Fill the available space and sit in the middle of it. */
  centered?: boolean;
}

/**
 * The orbiting mark from the boot splash (see `index.html`), at any size, so
 * loading looks the same wherever it happens: the logo's round-capped sweep
 * circling the orb.
 */
export const Spinner = ({
  size,
  inheritColor = false,
  centered = false,
}: SpinnerProps) => {
  const mark = (
    <Mark
      $size={size ?? (centered ? '4rem' : undefined)}
      $inheritColor={inheritColor}
      aria-hidden
    >
      <System>
        <Sweep viewBox='0 0 100 100' fill='none'>
          {/* The logo's sweep (brand/src/place-mark.svg): 270 degrees,
              centred on the orb. */}
          <path
            d='M74 50 A 24 24 0 1 1 50 26'
            stroke='currentColor'
            strokeWidth='14'
            strokeLinecap='round'
          />
        </Sweep>
      </System>
      <Orb />
    </Mark>
  );

  return centered ? (
    <Centered role='status' aria-label='Loading'>
      {mark}
    </Centered>
  ) : (
    mark
  );
};

const Centered = styled.div`
  display: flex;
  align-items: center;
  justify-content: center;
  box-sizing: border-box;
  width: 100%;
  /* Percentage heights only resolve when the parent's height is definite
     (e.g. <Main>). In a flex column the spinner instead grows to fill what is
     left, and anywhere else the minimum keeps it from collapsing to a strip. */
  height: 100%;
  min-height: 12rem;
  flex: 1 1 auto;
  align-self: stretch;
`;

const Mark = styled.span<{ $size?: string; $inheritColor: boolean }>`
  --spinner-size: ${p => p.$size || '50px'};
  --spinner-color: ${p =>
    p.$inheritColor ? 'currentColor' : p.theme.colors.text};
  position: relative;
  display: inline-block;
  flex-shrink: 0;
  width: var(--spinner-size);
  height: var(--spinner-size);
  max-width: 100%;
  max-height: 100%;
  vertical-align: middle;
  color: var(--spinner-color);
`;

const System = styled.span`
  position: absolute;
  inset: 0;
  animation: spinner-orbit 2.4s linear infinite;

  @keyframes spinner-orbit {
    to {
      rotate: 360deg;
    }
  }

  @media (prefers-reduced-motion: reduce) {
    animation-duration: 8s;
  }
`;

const Sweep = styled.svg`
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
`;

const Orb = styled.span`
  position: absolute;
  left: 50%;
  top: 50%;
  width: 24%;
  height: 24%;
  translate: -50% -50%;
  border-radius: 50%;
  background: linear-gradient(270deg, #01ecff, #2210ff);
  box-shadow: 0 0 0.6em rgba(0, 194, 255, 0.45);
`;
