import { useEffect } from 'react';
import {
  useString,
  useResource,
  Resource,
  type OptionalClass,
  dataBrowser,
  collections,
  server,
  core,
} from '@tomic/react';

import { ContainerNarrow } from '../components/Containers';
import Collection from '../views/CollectionPage';
import EndpointPage from './EndpointPage';
import DrivePage from './DrivePage';
import RedirectPage from './RedirectPage';
import InvitePage from './InvitePage';
import { DocumentPage } from './DocumentPage';
import ErrorPage, { ErrorBoundary } from './ErrorPage';
import { ClassPage } from './ClassPage';
import { FilePage } from './File/FilePage';
import { ResourcePageDefault } from './ResourcePageDefault';
import { Spinner } from '../components/Spinner';
import { ChatRoomPage } from './ChatRoomPage';
import { MessagePage } from './MessagePage';
import { BookmarkPage } from './BookmarkPage/BookmarkPage';
import { ImporterPage } from './ImporterPage.jsx';
import { FolderPage } from './FolderPage';
import { ArticlePage } from './Article';
import { TablePage } from './TablePage';
import { Main } from '../components/Main';
import { OntologyPage } from './OntologyPage';
import { TagPage } from './TagPage/TagPage';

/** These properties are passed to every View at Page level */
export type ResourcePageProps<Subject extends OptionalClass = never> = {
  resource: Resource<Subject>;
};

type Props = {
  subject: string;
};

/**
 * Renders a Resource and all its Properties in a random order. Title
 * (shortname) is rendered prominently at the top. If the Resource has a
 * particular Class, it will render a different Component.
 */
function ResourcePage({ subject }: Props): JSX.Element {
  const resource = useResource(subject);
  const [klass] = useString(resource, core.properties.isA);

  // The body can have an inert attribute when the user navigated from an open dialog.
  // we remove it to make the page becomes interavtive again.
  useEffect(() => {
    document.body.removeAttribute('inert');
  }, []);

  if (resource.loading) {
    return (
      <Main subject={subject}>
        <ContainerNarrow>
          <p>Loading...</p>
          <Spinner />
        </ContainerNarrow>
      </Main>
    );
  }

  if (resource.error) {
    return (
      <Main subject={subject}>
        <ErrorPage resource={resource} />
      </Main>
    );
  }

  const ReturnComponent = selectComponent(klass!);

  return (
    <Main subject={subject}>
      <ErrorBoundary>
        <ReturnComponent resource={resource} />
      </ErrorBoundary>
    </Main>
  );
}

function selectComponent(klass: string) {
  switch (klass) {
    case collections.classes.collection:
      return Collection;
    case server.classes.endpoint:
      return EndpointPage;
    case server.classes.drive:
      return DrivePage;
    case server.classes.redirect:
      return RedirectPage;
    case server.classes.invite:
      return InvitePage;
    case dataBrowser.classes.document:
      return DocumentPage;
    case core.classes.class:
      return ClassPage;
    case server.classes.file:
      return FilePage;
    case dataBrowser.classes.chatroom:
      return ChatRoomPage;
    case dataBrowser.classes.message:
      return MessagePage;
    case dataBrowser.classes.bookmark:
      return BookmarkPage;
    case dataBrowser.classes.importer:
      return ImporterPage;
    case dataBrowser.classes.folder:
      return FolderPage;
    case dataBrowser.classes.article:
      return ArticlePage;
    case dataBrowser.classes.table:
      return TablePage;
    case core.classes.ontology:
      return OntologyPage;
    case dataBrowser.classes.tag:
      return TagPage;
    default:
      return ResourcePageDefault;
  }
}

export default ResourcePage;
