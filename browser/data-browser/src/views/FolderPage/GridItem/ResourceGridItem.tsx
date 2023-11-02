import {
  core,
  dataBrowser,
  server,
  useResource,
  useString,
  useTitle,
} from '@tomic/react';
import React, { useCallback, useMemo } from 'react';
import { styled } from 'styled-components';
import { constructOpenURL } from '../../../helpers/navigation';
import { getIconForClass } from '../iconMap';
import { BookmarkGridItem } from './BookmarkGridItem';
import { BasicGridItem } from './BasicGridItem';
import { GridCard, GridItemTitle, GridItemWrapper } from './components';
import { DefaultGridItem } from './DefaultGridItem';
import { GridItemViewProps } from './GridItemViewProps';
import { FaFolder } from 'react-icons/fa';
import { ChatRoomGridItem } from './ChatRoomGridItem';
import { DocumentGridItem } from './DocumentGridItem';
import { FileGridItem } from './FileGridItem';
import { ErrorBoundary } from '../../ErrorPage';
import { useNavigateWithTransition } from '../../../hooks/useNavigateWithTransition';
import { LoaderBlock } from '../../../components/Loader';
import { ArticleGridItem } from './ArticleGridItem';

export interface ResourceGridItemProps {
  subject: string;
}

const gridItemMap = new Map<string, React.FC<GridItemViewProps>>([
  [dataBrowser.classes.bookmark, BookmarkGridItem],
  [core.classes.class, BasicGridItem],
  [core.classes.property, BasicGridItem],
  [dataBrowser.classes.chatroom, ChatRoomGridItem],
  [dataBrowser.classes.document, DocumentGridItem],
  [server.classes.file, FileGridItem],
  [dataBrowser.classes.article, ArticleGridItem],
]);

function getResourceRenderer(
  classSubject: string,
): React.FC<GridItemViewProps> {
  return gridItemMap.get(classSubject) ?? DefaultGridItem;
}

export function ResourceGridItem({
  subject,
}: ResourceGridItemProps): JSX.Element {
  const navigate = useNavigateWithTransition();
  const resource = useResource(subject);
  const [title] = useTitle(resource);

  const [classTypeSubject] = useString(resource, core.properties.isA);
  const classType = useResource(classTypeSubject);
  const [classTypeName] = useTitle(classType);

  const Icon = getIconForClass(classTypeSubject ?? '');

  const handleClick = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();

      navigate(constructOpenURL(subject));
    },
    [subject, navigate],
  );

  const Resource = useMemo(() => {
    return getResourceRenderer(classTypeSubject ?? '');
  }, [classTypeSubject]);

  if (classTypeSubject === undefined) {
    return <Loader />;
  }

  const isFolder = classTypeSubject === dataBrowser.classes.folder;

  const transitionSubject = isFolder ? undefined : subject;

  return (
    <GridItemWrapper onClick={handleClick} href={subject}>
      <GridItemTitle subject={transitionSubject}>{title}</GridItemTitle>
      {isFolder ? (
        <FolderIcon />
      ) : (
        <GridCard subject={transitionSubject}>
          <ClassBanner>
            <Icon />
            <span>{classTypeName}</span>
          </ClassBanner>
          <ErrorBoundary FallBackComponent={GridItemError}>
            <Resource resource={resource} />
          </ErrorBoundary>
        </GridCard>
      )}
    </GridItemWrapper>
  );
}

const ClassBanner = styled.div`
  display: flex;
  background-color: ${p => p.theme.colors.bg};
  border-top-left-radius: ${p => p.theme.radius};
  border-top-right-radius: ${p => p.theme.radius};
  align-items: center;
  gap: 0.5rem;
  justify-content: center;
  padding-block: var(--card-banner-padding);
  color: ${p => p.theme.colors.textLight};

  border-bottom: 1px solid ${p => p.theme.colors.bg2};
  span {
    text-transform: capitalize;
  }
`;

const FolderIcon = styled(FaFolder)`
  height: 100%;
  width: 100%;
  color: ${p => p.theme.colors.textLight};
  transition: color 0.1s ease-in-out;

  ${GridItemWrapper}:hover & {
    color: ${p => p.theme.colors.main};
  }
`;

interface GridItemErrorProps {
  error: Error;
}

const GridItemError: React.FC<GridItemErrorProps> = ({ error }) => {
  return <GridItemErrorWrapper>{error.message}</GridItemErrorWrapper>;
};

const GridItemErrorWrapper = styled.div`
  color: ${p => p.theme.colors.alert};
  text-align: center;
`;

const Loader = styled(LoaderBlock)`
  --loader-bg-to: ${p => p.theme.colors.bgBody};
  height: unset;
  aspect-ratio: 1/1;
`;
