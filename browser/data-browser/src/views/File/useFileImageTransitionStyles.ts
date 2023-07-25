import { getTransitionName } from '../../helpers/transitionName';
import { useGlobalStylesWhileMounted } from '../../hooks/useGlobalStylesWhileMounted';

export function useFileImageTransitionStyles(subject: string) {
  const name = getTransitionName('file-image', subject);

  useGlobalStylesWhileMounted(`
    ::view-transition-old(${name}),
    ::view-transition-new(${name}) {
      mix-blend-mode: normal;
      height: 100%;
      overflow: clip;
    }

    ::view-transition-old(${name}) {
      object-fit: contain;
    }

    ::view-transition-new(${name}) {
      animation: none;
      object-fit: cover;
    }

  `);

  return { viewTransitionName: name } as Record<string, string>;
}
