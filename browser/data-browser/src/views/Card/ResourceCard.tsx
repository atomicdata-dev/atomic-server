import { Suspense, useState, type JSX } from 'react';
import { useInView } from 'react-intersection-observer';
import {
  useString,
  useResource,
  useTitle,
  core,
  server,
  dataBrowser,
  collections,
  commits,
  useArray,
  ai,
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
import { styled } from 'styled-components';
import { ResourceCardTitle } from './ResourceCardTitle';
import { Column, Row } from '../../components/Row';
import { Tag } from '../../components/Tag';
import { ResourceContextMenu } from '../../components/ResourceContextMenu';
import { AIChatContentCard } from './AIChatContentCard';
import { DocumentV2Card } from './DocumentV2Card';
import { MeetingCard } from './MeetingCard';
import { HideInPrint } from '@components/HideInPrint';
import { useOnValueChange } from '@helpers/useOnValueChange';
import { FolderCard } from './FolderCard';
import { Spinner } from '../../components/Spinner';

interface ResourceCardProps extends CardViewPropsBase {
  /** The subject URL - the identifier of the resource. */
  subject: string;
}

/**
 * Renders a Resource and all its Properties in a random order. Title
 * (shortname) is rendered prominently at the top.
 */
function ResourceCard(
  props: ResourceCardProps &
    JSX.IntrinsicElements['div'] & { className?: string },
): JSX.Element {
  const { initialInView, className, ...rest } = props;

  // The (more expensive) ResourceCardInner is only rendered when the component has been in View
  const { ref, inView } = useInView({
    threshold: 0,
    initialInView,
  });
  const [isShown, setIsShown] = useState(inView);

  useOnValueChange(() => {
    if (inView && !isShown) {
      setIsShown(true);
    }
  }, [inView, isShown]);

  return (
    <Suspense>
      <Card {...rest} ref={ref} about={props.subject} className={className}>
        {isShown ? (
          <ResourceCardInner {...props} />
        ) : (
          <>
            <h2>
              <AtomicLink subject={props.subject}>{props.subject}</AtomicLink>
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
  const [klass] = useString(resource, core.properties.isA);

  if (resource.loading) {
    return <Spinner size='1.5rem' />;
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
    case collections.classes.collection:
      return <CollectionCard resource={resource} {...props} />;
    case server.classes.file:
      return <FileCard resource={resource} {...props} />;
    case dataBrowser.classes.message:
      return <MessageCard resource={resource} {...props} />;
    case dataBrowser.classes.bookmark:
      return <BookmarkCard resource={resource} {...props} />;
    case dataBrowser.classes.paragraph:
      return <ElementCard resource={resource} {...props} />;
    case dataBrowser.classes.article:
      return <ArticleCard resource={resource} {...props} />;
    case ai.classes.textPart:
      return <AIChatContentCard resource={resource} {...props} />;
    case dataBrowser.classes.documentV2:
      return <DocumentV2Card resource={resource} {...props} />;
    case dataBrowser.classes.meeting:
      return <MeetingCard resource={resource} {...props} />;
    case dataBrowser.classes.folder:
      return <FolderCard resource={resource} {...props} />;
    default:
      return <ResourceCardDefault resource={resource} {...props} />;
  }
}

/**
 * Bookkeeping a reader of a card (a record embedded in a document, say) has no
 * use for: when and where the resource was made, and its position in a table.
 */
const cardHiddenProps = [
  ...defaultHiddenProps,
  commits.properties.createdAt,
  dataBrowser.properties.sortOrder,
  'https://atomicdata.dev/properties/drive',
];

export function ResourceCardDefault({
  resource,
  small,
}: CardViewProps): JSX.Element {
  const [isA] = useArray(resource, core.properties.isA);
  const isAResource = useResource(isA[0]);
  const [tags] = useArray(resource, dataBrowser.properties.tags);
  const [description] = useString(resource, core.properties.description);

  return (
    <Column gap='0.5rem'>
      <ResourceCardTitle resource={resource}>
        <Row center gap='1ch'>
          <span>{isAResource.title}</span>
          <HideInPrint>
            <ResourceContextMenu simple subject={resource.subject} />
          </HideInPrint>
        </Row>
      </ResourceCardTitle>
      <Row gap='1ch' style={{ fontSize: '0.8rem' }}>
        {tags.map(tag => (
          <Tag subject={tag} key={tag} />
        ))}
      </Row>
      {/* Without a description there is nothing to show; an empty form field
       * here reads as a stray "Empty" line above the real properties. */}
      {description && (
        <DescriptionWrapper>
          <ValueForm
            resource={resource}
            propertyURL={core.properties.description}
          />
        </DescriptionWrapper>
      )}
      {!small && (
        <AllProps
          basic
          labelByName
          resource={resource}
          except={cardHiddenProps}
          editable
        />
      )}
    </Column>
  );
}

export default ResourceCard;

const DescriptionWrapper = styled.div`
  max-height: 10rem;
  overflow: hidden;
`;
