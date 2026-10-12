import { useCallback, useEffect, useRef, useState, type JSX } from 'react';
import { css, keyframes, styled } from 'styled-components';

type Status = 'loading' | 'loaded' | 'error';

export interface AvatarImgProps {
  /** `undefined` while the address is still being resolved. */
  src: string | undefined;
  alt: string;
  className?: string;
  /** Shown instead of the image when it cannot be loaded. */
  fallback?: JSX.Element;
}

/**
 * An avatar image that never collapses and never stays broken.
 *
 * - The wrapper is always a block of the size its parent gives it, so the
 *   layout beside it is the same before, during and after the load. Until the
 *   bytes arrive it shows a pulsing placeholder.
 * - An image that is already decoded (same `src` as a moment ago, cached by
 *   the browser) is shown at once, without the placeholder.
 * - A failed load is not remembered: the image is requested again when the
 *   page is shown again (back/forward navigation, bfcache restore, the tab
 *   becoming visible) and when the address changes. A loaded image is left
 *   alone.
 */
export function AvatarImg({
  src,
  alt,
  className,
  fallback,
}: AvatarImgProps): JSX.Element {
  // The status belongs to one address; a new address starts over.
  const [state, setState] = useState<{ src?: string; status: Status }>({
    status: 'loading',
  });
  const [attempt, setAttempt] = useState(0);
  const imgRef = useRef<HTMLImageElement | null>(null);
  const status: Status = state.src === src ? state.status : 'loading';

  const update = useCallback(
    (next: Status) => {
      setState({ src, status: next });
    },
    [src],
  );

  // Already complete in the browser cache: no placeholder flash.
  useEffect(() => {
    const img = imgRef.current;

    if (img?.complete && img.naturalWidth > 0) update('loaded');
  }, [src, attempt, update]);

  // Retry whatever is not loaded when the page comes back.
  useEffect(() => {
    const retry = () => {
      const img = imgRef.current;

      // A bfcache restore can leave a decoded-then-dropped image blank.
      if (img?.complete && img.naturalWidth === 0 && src) {
        update('loading');
        setAttempt(a => a + 1);

        return;
      }

      if (status === 'error') {
        update('loading');
        setAttempt(a => a + 1);
      }
    };

    const onVisible = () => {
      if (document.visibilityState === 'visible') retry();
    };

    window.addEventListener('pageshow', retry);
    document.addEventListener('visibilitychange', onVisible);

    return () => {
      window.removeEventListener('pageshow', retry);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [src, status, update]);

  if (status === 'error' && fallback) {
    return <Frame className={className}>{fallback}</Frame>;
  }

  return (
    <Frame
      className={className}
      $placeholder={status !== 'loaded'}
      data-avatar-status={src ? status : 'loading'}
    >
      {src && (
        <Img
          // A fresh element per attempt, so a failed request is re-issued.
          key={`${src}|${attempt}`}
          ref={imgRef}
          src={src}
          alt={alt}
          $visible={status === 'loaded'}
          onLoad={() => update('loaded')}
          onError={() => update('error')}
        />
      )}
    </Frame>
  );
}

const pulse = keyframes`
  0%, 100% { opacity: 1; }
  50% { opacity: 0.55; }
`;

const Frame = styled.span<{ $placeholder?: boolean }>`
  display: inline-block;
  position: relative;
  width: 100%;
  height: 100%;
  border-radius: inherit;
  overflow: hidden;
  vertical-align: top;
  background: ${p => (p.$placeholder ? p.theme.colors.bg2 : 'transparent')};
  ${p =>
    p.$placeholder &&
    css`
      animation: ${pulse} 1.4s ease-in-out infinite;

      @media (prefers-reduced-motion: reduce) {
        animation: none;
      }
    `}
`;

const Img = styled.img<{ $visible: boolean }>`
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  object-fit: cover;
  display: block;
  opacity: ${p => (p.$visible ? 1 : 0)};
`;
