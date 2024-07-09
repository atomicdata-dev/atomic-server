import { useEffect } from 'react';
import {
  useString,
  useResource,
  properties,
  Resource,
  urls,
  type OptionalClass,
} from '@tomic/react';
import { vihreat } from '../vihreat/vihreat';

import { ContainerNarrow } from '../components/Containers';
import Collection from '../views/CollectionPage';
import EndpointPage from './EndpointPage';
import DrivePage from './DrivePage';
import RedirectPage from './RedirectPage';
import InvitePage from './InvitePage';
import { DocumentPage } from './DocumentPage';
import { ProgramPage } from '../vihreat/ProgramPage';
import ErrorPage, { ErrorBoundary } from './ErrorPage';
import { ClassPage } from './ClassPage';
import { FilePage } from './File/FilePage';
import { ResourcePageDefault } from './ResourcePageDefault';
import { Spinner } from '../components/Spinner';
import { ChatRoomPage } from './ChatRoomPage';
import { MessagePage } from './MessagePage';
import { BookmarkPage } from './BookmarkPage/BookmarkPage';
import { ImporterPage } from './ImporterPage.jsx';
import Parent from '../components/Parent';
import { FolderPage } from './FolderPage';
import { ArticlePage } from './Article';
import { TablePage } from './TablePage';
import { Main } from '../components/Main';
import { OntologyPage } from './OntologyPage';

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
  const [klass] = useString(resource, properties.isA);

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
    <>
      <Parent resource={resource} />
      <Main subject={subject}>
        <ErrorBoundary>
          <ReturnComponent resource={resource} />
        </ErrorBoundary>
      </Main>
    </>
  );
}

function selectComponent(klass: string) {
  switch (klass) {
    case urls.classes.collection:
      return Collection;
    case urls.classes.endpoint:
      return EndpointPage;
    case urls.classes.drive:
      return DrivePage;
    case urls.classes.redirect:
      return RedirectPage;
    case urls.classes.invite:
      return InvitePage;
    case urls.classes.document:
      return DocumentPage;
    case urls.classes.class:
      return ClassPage;
    case urls.classes.file:
      return FilePage;
    case urls.classes.chatRoom:
      return ChatRoomPage;
    case urls.classes.message:
      return MessagePage;
    case urls.classes.bookmark:
      return BookmarkPage;
    case urls.classes.importer:
      return ImporterPage;
    case urls.classes.folder:
      return FolderPage;
    case urls.classes.article:
      return ArticlePage;
    case urls.classes.table:
      return TablePage;
    case urls.classes.ontology:
      return OntologyPage;
    case vihreat.classes.program:
      return ProgramPage;
    default:
      return ResourcePageDefault;
  }
}

export default ResourcePage;
