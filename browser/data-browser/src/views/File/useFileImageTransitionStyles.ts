import {
  FILE_IMAGE_TRANSITION_TAG,
  getTransitionName,
} from '../../helpers/transitionName';
import { useGlobalStylesWhileMounted } from '../../hooks/useGlobalStylesWhileMounted';

export function useFileImageTransitionStyles(subject: string) {
  let css = '';
  let name = 'none';

  try {
    name = getTransitionName(FILE_IMAGE_TRANSITION_TAG, subject);
    css = `
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
    `;
  } catch (e) {
    // Do nothing
  }

  useGlobalStylesWhileMounted(css);

  return { viewTransitionName: name } as Record<string, string>;
}
