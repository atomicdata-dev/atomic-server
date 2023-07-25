import * as React from 'react';
import { Client } from '@tomic/react';
import ResourcePage from '../views/ResourcePage';
import { useCurrentSubject } from '../helpers/useCurrentSubject';
import { Search } from './SearchRoute';
import { About } from './AboutRoute';

/** Renders either the Welcome page, an Individual resource, or search results. */
const Show: React.FunctionComponent = () => {
  // Value shown in navbar, after Submitting
  const [subject] = useCurrentSubject();

  if (subject === undefined || subject === '') {
    return <About />;
  }

  if (Client.isValidSubject(subject)) {
    return <ResourcePage key={subject} subject={subject} />;
  } else {
    return <Search />;
  }
};

export default Show;
