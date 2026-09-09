import * as React from 'react';
import { Client, useStore } from '@tomic/react';
import ResourcePage from '../views/ResourcePage';
import { Search } from './Search/SearchRoute';
import { About } from './AboutRoute';
import { createRoute, useNavigate } from '@tanstack/react-router';
import { appRoute } from './RootRoutes';
import { pathNames, paths } from './paths';
import { useSettings } from '../helpers/AppSettings';
import { isOriginWithoutNode } from '../helpers/originNode';

export type ShowRouteSearch = {
  subject: string;
  /**
   * The active View of a Table, so switching tabs is linkable and lands in
   * browser history. Absent = the table's default view.
   */
  view?: string;
  editColumn?: string;
};

export const ShowRoute = createRoute({
  path: pathNames.show,
  component: () => <ShowComponent />,
  getParentRoute: () => appRoute,
  validateSearch: (search): ShowRouteSearch => ({
    subject: (search.subject as string) ?? '',
    view: (search.view as string) || undefined,
    editColumn: (search.editColumn as string) || undefined,
  }),
});

/** Renders either the Welcome page, an Individual resource, or search results. */
export const ShowComponent: React.FunctionComponent = () => {
  // Value shown in navbar, after Submitting
  const subject = ShowRoute.useSearch({ select: state => state.subject });
  const { agent } = useSettings();
  const store = useStore();
  const navigate = useNavigate();

  // Signed out on an origin that runs no node: nothing can load until a
  // sign-in restores the data, so go straight to the sign-in step with the
  // subject as `next`. Without this the page first fetches, shows
  // "Loading…", fails as "not available locally" and only then redirects
  // from ErrorPage — several seconds of a spinner between the portal link
  // and the sign-in screen.
  const signInFirst =
    !agent &&
    Client.isValidSubject(subject) &&
    isOriginWithoutNode(store.getServerUrl());

  React.useEffect(() => {
    if (!signInFirst) return;

    navigate({
      to: paths.welcome,
      search: { next: subject, from_portal: undefined },
      replace: true,
    });
  }, [signInFirst, subject, navigate]);

  if (signInFirst) {
    return null;
  }

  if (subject === undefined || subject === '') {
    return <About />;
  }

  if (Client.isValidSubject(subject)) {
    return <ResourcePage key={subject} subject={subject} />;
  } else {
    return <Search />;
  }
};
