import React, { Suspense, useEffect, useState } from 'react';
import { useInView } from 'react-intersection-observer';
import {
  useString,
  useResource,
  useTitle,
  properties,
  urls,
} from '@tomic/react';
import AllProps from '../../components/AllProps';
import { AtomicLink } from '../../components/AtomicLink';
import { Card } from '../../components/Card';
import CollectionCard from './CollectionCard';
import { ErrorLook } from '../../components/ErrorLook';
import { ValueForm } from '../../components/forms/ValueForm';
import FileCard from '../File/FileCard';
import { defaultHiddenProps } from '../ResourcePageDefault';
import { MessageCard } from './MessageCard';
import { BookmarkCard } from './BookmarkCard.jsx';
import { CardViewProps, CardViewPropsBase } from './CardViewProps';
import { ElementCard } from './ElementCard';
import { ArticleCard } from '../Article';

interface ResourceCardProps extends CardViewPropsBase {
  /** The subject URL - the identifier of the resource. */
  subject: string;
}

/**
 * Renders a Resource and all its Properties in a random order. Title
 * (shortname) is rendered prominently at the top.
 */
function ResourceCard(
  props: ResourceCardProps & JSX.IntrinsicElements['div'],
): JSX.Element {
  const { subject, initialInView } = props;
  const [isShown, setIsShown] = useState(false);
  // The (more expensive) ResourceCardInner is only rendered when the component has been in View
  const { ref, inView } = useInView({
    threshold: 0,
    initialInView,
  });

  useEffect(() => {
    if (inView && !isShown) {
      setIsShown(true);
    }
  }, [inView, isShown]);

  return (
    <Suspense>
      <Card ref={ref} {...props} about={subject}>
        {isShown ? (
          <ResourceCardInner {...props} />
        ) : (
          <>
            <h2>
              <AtomicLink subject={subject}>{subject}</AtomicLink>
            </h2>
            <p>Resource is loading...</p>
          </>
        )}
      </Card>
    </Suspense>
  );
}

/**
 * The expensive view logic for a default Resource. This should only be rendered
 * if the card is in the viewport
 */
function ResourceCardInner(props: ResourceCardProps): JSX.Element {
  const { subject } = props;
  const resource = useResource(subject);
  const [title] = useTitle(resource);
  const [klass] = useString(resource, properties.isA);

  if (resource.loading) {
    return <p>Loading...</p>;
  }

  if (resource.error) {
    return (
      <ErrorLook>
        <AtomicLink subject={subject}>
          <h2>{title}</h2>
        </AtomicLink>
        {resource.error.message}
      </ErrorLook>
    );
  }

  /** Check if there exists a View for this Class. These should be registered in `../views` */
  switch (klass) {
    case urls.classes.collection:
      return <CollectionCard resource={resource} {...props} />;
    case urls.classes.file:
      return <FileCard resource={resource} {...props} />;
    case urls.classes.message:
      return <MessageCard resource={resource} {...props} />;
    case urls.classes.bookmark:
      return <BookmarkCard resource={resource} {...props} />;
    case urls.classes.elements.paragraph:
      return <ElementCard resource={resource} {...props} />;
    case urls.classes.article:
      return <ArticleCard resource={resource} {...props} />;
    default:
      return <ResourceCardDefault resource={resource} {...props} />;
  }
}

export function ResourceCardDefault({
  resource,
  small,
}: CardViewProps): JSX.Element {
  const [title] = useTitle(resource);

  return (
    <React.Fragment>
      <AtomicLink subject={resource.getSubject()}>
        <h2>{title}</h2>
      </AtomicLink>
      <ValueForm
        resource={resource}
        propertyURL={urls.properties.description}
      />
      {!small && (
        <AllProps resource={resource} except={defaultHiddenProps} editable />
      )}
    </React.Fragment>
  );
}

export default ResourceCard;
