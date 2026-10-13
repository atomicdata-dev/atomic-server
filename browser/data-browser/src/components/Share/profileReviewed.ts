const PROFILE_REVIEWED_KEY = 'inviteProfileReviewed';

/**
 * Share opens on the invite, so without this someone who skips the optional
 * picture would get the profile step on every Share click. Once per agent on
 * this device is enough of a nudge.
 */
export function profileReviewedBefore(agent: string | undefined): boolean {
  if (!agent) return false;

  try {
    return localStorage.getItem(PROFILE_REVIEWED_KEY) === agent;
  } catch {
    return false;
  }
}

export function rememberProfileReviewed(agent: string): void {
  try {
    localStorage.setItem(PROFILE_REVIEWED_KEY, agent);
  } catch {
    /* Without storage the step simply shows again next time. */
  }
}
