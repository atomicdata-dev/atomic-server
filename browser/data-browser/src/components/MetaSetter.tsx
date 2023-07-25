import {
  properties,
  unknownSubject,
  useResource,
  useString,
  useTitle,
} from '@tomic/react';
import React from 'react';
import { Helmet } from 'react-helmet-async';
import { useSettings } from '../helpers/AppSettings';
import { useCurrentSubject } from '../helpers/useCurrentSubject';

/** Sets various HTML meta tags, depending on the currently opened resource */
export function MetaSetter(): JSX.Element {
  const { mainColor, darkMode } = useSettings();
  const [subject] = useCurrentSubject();
  const resource = useResource(subject);
  let [title] = useTitle(resource);
  let [description] = useString(resource, properties.description);
  const hasResource =
    resource.isReady() && resource.getSubject() !== unknownSubject;

  title = hasResource && title ? title : 'Atomic Data';
  description =
    hasResource && description
      ? description
      : 'The easiest way to create and share linked data.';

  return (
    <Helmet>
      <title>{title}</title>
      <meta name='theme-color' content={darkMode ? 'black' : 'white'} />
      <meta name='theme-color' content={darkMode ? 'black' : 'white'} />
      <meta
        name='apple-mobile-web-app-status-bar-style'
        content={darkMode ? 'black' : 'default'}
      />
      <meta name='msapplication-TileColor' content={mainColor} />
      <meta name='description' content={description} />
      <meta property='og:title' content={title} />
      <meta property='og:description' content={description} />
      <meta property='og:url' content={subject} />
    </Helmet>
  );
}
