import { PeerInvitePage } from '../views/PeerInvitePage';
import { createRoute } from '@tanstack/react-router';
import { useResource, useStore } from '@tomic/react';
import InvitePage from '../views/InvitePage';
import { appRoute } from './RootRoutes';
import { pathNames } from './paths';

/**
 * /app/invite?token=... route.
 * Constructs the server-side invite subject from the token and renders the
 * InvitePage onboarding UX.
 */
export const InviteRoute = createRoute({
  path: pathNames.invite,
  component: InviteRouteComponent,
  getParentRoute: () => appRoute,
});

function InviteRouteComponent() {
  const store = useStore();
  const token = new URLSearchParams(window.location.search).get('token');

  if (!token) {
    return <p>No invite token provided.</p>;
  }

  let browserInvite = false;
  let invalid = false;

  try {
    const data = JSON.parse(atob(token));
    browserInvite =
      data['https://atomicdata.dev/properties/invite/transport'] === 'webrtc';
  } catch {
    invalid = true;
  }

  if (invalid) return <p>Invalid invitation.</p>;
  if (browserInvite) return <PeerInvitePage token={token} />;

  const subject = `${store.getServerUrl()}/invites?token=${encodeURIComponent(token)}`;

  return <InvitePageHost subject={subject} key={subject} />;
}

/**
 * Render `InvitePage` DIRECTLY instead of routing through `ResourcePage`'s
 * class-based component selection.
 *
 * The `/app/invite` route already KNOWS the subject is an invite, so it must
 * not depend on the resource's `isA` materialising. That is racy: a server
 * snapshot can arrive before Loro WASM is ready (notably in an insecure
 * context — plain HTTP on a non-localhost origin — where the WASM is
 * unstable), leaving the resource with no class. When that happened,
 * `ResourcePage.selectComponent` fell back to `ResourcePageDefault` and the
 * user saw the raw resource (a class-less / "agent"-looking blob) with no
 * Accept button and no redirect, instead of the invite welcome screen.
 *
 * The accept flow only needs the token (which is in the URL), not the
 * resource's class — so rendering InvitePage unconditionally is both correct
 * and robust against the materialisation race.
 */
function InvitePageHost({ subject }: { subject: string }) {
  const resource = useResource(subject);

  return <InvitePage resource={resource} />;
}
