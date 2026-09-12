export const FILE_IMAGE_TRANSITION_TAG = 'file-image';
export const SIDEBAR_TRANSITION_TAG = 'sidebar';
export const PAGE_TITLE_TRANSITION_TAG = 'page-title';
/**
 * Distinct from PAGE_TITLE_TRANSITION_TAG: the meeting side panel's title
 * shows the same resource as the main page title whenever you're viewing the
 * meeting itself (MeetingPage's own EditableTitle + the panel's). Two
 * simultaneously-rendered elements can't share a view-transition-name — the
 * browser skips the transition and warns. Same subject, different UI slot,
 * so it needs its own tag rather than colliding with the page title's.
 */
export const MEETING_PANEL_TITLE_TRANSITION_TAG = 'meeting-panel-title';
export const RESOURCE_PAGE_TRANSITION_TAG = 'resource-page';
export const BREADCRUMB_BAR_TRANSITION_TAG = 'breadcrumb-bar';
export const NAVBAR_TRANSITION_TAG = 'navbar';

const hashStringWithCYRB53 = (str: string, seed = 0) => {
  let h1 = 0xdeadbeef ^ seed,
    h2 = 0x41c6ce57 ^ seed;

  for (let i = 0, ch: number; i < str.length; i++) {
    ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }

  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
  h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
  h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);

  return 4294967296 * (2097151 & h2) + (h1 >>> 0);
};

export function getTransitionName(tag: string, subject: string | undefined) {
  if (!subject) {
    throw new Error('Subject is required for transition name');
  }

  // URL's are not allowed in view-transition-name so we hash the subject.
  return `${tag}-${hashStringWithCYRB53(subject ?? '')}`;
}

export function transitionName(tag: string, subject: string | undefined) {
  let name: string;

  try {
    name = getTransitionName(tag, subject);
  } catch (e) {
    return 'view-transition-name: none';
  }

  // Class lets us target a *kind* of snapshot (title vs page) without
  // enumerating hashed names. Firefox needs different sizing rules per
  // kind — a global `block-size: 100%` on `*` inflates card→page morphs.
  return `view-transition-name: ${name}; view-transition-class: ${tag}`;
}

export function getTransitionStyle(tag: string, subject: string | undefined) {
  let name: string;

  try {
    name = getTransitionName(tag, subject);
  } catch (e) {
    return {};
  }

  return {
    viewTransitionName: name,
    viewTransitionClass: tag,
  };
}
