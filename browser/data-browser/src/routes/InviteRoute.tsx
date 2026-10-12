import { PeerInvitePage } from '../views/PeerInvitePage';
import { createRoute, useNavigate } from '@tanstack/react-router';
import { server, useServerURL, useResource, useStore } from '@tomic/react';
import { useEffect, useState, type JSX } from 'react';
import {
  alreadyHasInviteAccess,
  readInviteGrant,
} from '../helpers/inviteAccess';
import { useSettings } from '../helpers/AppSettings';
import { constructOpenURL } from '../helpers/navigation';
import { isDev } from '../config';
import { inviteNodeCandidates, pickInviteNode } from '../helpers/inviteNode';
import {
  isOriginWithoutNode,
  originMayLackNode,
  probeOriginForNode,
} from '../helpers/originNode';
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

  return (
    <OpenIfAlreadyShared token={token}>
      {browserInvite ? (
        <PeerInvitePage token={token} />
      ) : (
        <NodeInvite token={token} />
      )}
    </OpenIfAlreadyShared>
  );
}

/**
 * Someone who already has what the invite grants (they made the link, or the
 * resource is already shared with them) goes straight to it: there is nothing
 * to accept, and on a host with no node the invite could not be resolved
 * anyway. Everyone else gets the invite screen.
 */
function OpenIfAlreadyShared({
  token,
  children,
}: {
  token: string;
  children: JSX.Element;
}) {
  const store = useStore();
  const navigate = useNavigate();
  const { agent, setDrive } = useSettings();
  const agentSubject = agent?.subject;
  const [grant] = useState(() => readInviteGrant(token));
  const [checked, setChecked] = useState(!agentSubject || !grant);

  useEffect(() => {
    if (!agentSubject || !grant) return;

    let active = true;

    void (async () => {
      const has = await alreadyHasInviteAccess(store, agentSubject, grant);
      if (!active) return;

      if (!has) {
        setChecked(true);

        return;
      }

      // A shared drive becomes the active one, as accepting would make it.
      const target = await store.getResource(grant.target).catch(() => {});
      if (!active) return;
      if (target?.hasClasses(server.classes.drive)) setDrive(grant.target);
      navigate({ to: constructOpenURL(grant.target), replace: true });
    })();

    return () => {
      active = false;
    };
  }, [grant, agentSubject, store, navigate, setDrive]);

  if (!checked) return <p>Opening invitation...</p>;

  return children;
}

/**
 * Opens the invite on the node it was made for.
 *
 * The invite is a resource on the drive's node, so the request has to go
 * there. The link says where that is (the origin it was opened on, or
 * `?server=`); the server this browser happened to have saved does not. A
 * hosted app origin such as `app.atomic.place` serves index.html for every
 * path, so asking it for the invite gave "Could not parse JSON ... Unrecognized
 * token '<'". When no node can be found the person is told, instead.
 */
function NodeInvite({ token }: { token: string }) {
  const store = useStore();
  const [, setServerUrl] = useServerURL();
  const candidates = inviteNodeCandidates({
    serverParam: new URLSearchParams(window.location.search).get('server'),
    locationOrigin: window.location.origin,
    storedServer: store.getServerUrl(),
    dev: isDev(),
  });
  const candidatesKey = candidates.join(' ');
  const [node, setNode] = useState<string | null | undefined>();

  useEffect(() => {
    let active = true;

    void (async () => {
      const pageOrigin = window.location.origin;

      // A hosted build can be served by something that is not a node.
      if (originMayLackNode() && candidates.includes(pageOrigin)) {
        await probeOriginForNode(pageOrigin);
      }

      if (!active) return;

      const chosen = pickInviteNode(candidates);

      if (chosen && chosen !== store.getServerUrl()) setServerUrl(chosen);

      setNode(chosen ?? null);
    })();

    return () => {
      active = false;
    };
    // oxlint-disable-next-line react-hooks/exhaustive-deps -- `candidatesKey` stands for `candidates`
  }, [candidatesKey, store, setServerUrl]);

  if (node === undefined) return <p>Opening invitation...</p>;

  if (node === null || isOriginWithoutNode(node)) {
    return (
      <p>
        This invitation cannot be opened here: {candidates[0]} does not run a
        server that holds the drive. Ask the person who invited you for a new
        link.
      </p>
    );
  }

  const subject = `${node}/invites?token=${encodeURIComponent(token)}`;

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
