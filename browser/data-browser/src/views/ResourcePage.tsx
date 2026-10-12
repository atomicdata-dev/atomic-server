import { useWebsiteClass } from '@chunks/Website/useWebsiteClass';
import { useEffect, useState, lazy, Suspense } from 'react';
import {
  useResource,
  useStore,
  Resource,
  type OptionalClass,
  dataBrowser,
  collections,
  server,
  core,
  ai,
  forms,
  notifications,
  conversations,
  useArray,
} from '@tomic/react';

import { ContainerNarrow } from '../components/Containers';
import Collection from '../views/CollectionPage';
import EndpointPage from './EndpointPage';
import DrivePage from './Drive/DrivePage';
import InvitePage from './InvitePage';
import { DocumentPage } from './DocumentPage';
import ErrorPage, { ErrorBoundary } from './ErrorPage';
import { ClassPage } from './ClassPage';
import { FilePage } from './File/FilePage';
import { ResourcePageDefault } from './ResourcePageDefault';
import { Spinner } from '../components/Spinner';
import { ChatRoomPage } from './ChatRoomPage';
import { ConversationPage } from './Conversation/ConversationPage';
import { InboxPage } from './InboxPage';
import { MessagePage } from './MessagePage';
import { ChatLogPage } from './ChatLogPage';
import { BookmarkPage } from './BookmarkPage/BookmarkPage';
import { ImporterPage } from './ImporterPage.jsx';
import { FolderPage } from './FolderPage';
import { ArticlePage } from './Article';
import { ForkBar } from '../components/ForkBar';
import { PendingForks } from '../components/PendingForks';
import { Main } from '../components/Main';
import { OntologyPage } from './OntologyPage';
import { TagPage } from './TagPage/TagPage';
import { AIChatPage } from '@views/AIChat/AIChatPage';
import { DocumentV2FullPage } from './Document/DocumentV2FullPage';
import { CanvasPage } from './Canvas/CanvasPage';
import { canvas } from '@tomic/lib';
import { InstallationPage } from '@views/Installation/InstallationPage';
import { useCustomViews } from '@components/CustomViewProvider';
import { PluginView } from './PluginView/PluginView';
import { MeetingPage } from './Meeting/MeetingPage';
import { useIsPlugin } from '@chunks/PluginRuns/PluginSection';
import { useAppClass } from '@chunks/PluginRuns/useDriveClass';

const TablePage = lazy(() =>
  import('../chunks/TablePage').then(m => ({ default: m.TablePage })),
);

const DashboardPage = lazy(() =>
  import('../chunks/DashboardPage').then(m => ({ default: m.DashboardPage })),
);

const WebsiteExportPage = lazy(() =>
  import('@chunks/Website/WebsiteExportPage').then(m => ({
    default: m.WebsiteExportPage,
  })),
);
const WebsitePage = lazy(() =>
  import('@chunks/Website/WebsitePage').then(m => ({ default: m.WebsitePage })),
);

const AtomicPluginPage = lazy(() =>
  import('@chunks/PluginRuns/PluginPage').then(m => ({
    default: m.PluginPage,
  })),
);

const ImportResolutionNotice = lazy(() =>
  import('@chunks/PluginRuns/ImportResolutionNotice').then(m => ({
    default: m.ImportResolutionNotice,
  })),
);

const AppPage = lazy(() =>
  import('../chunks/AppPage').then(m => ({ default: m.AppPage })),
);

const FormBuilderPage = lazy(() =>
  import('../chunks/FormBuilder').then(m => ({ default: m.FormBuilderPage })),
);

/** These properties are passed to every View at Page level */
export type ResourcePageProps<Subject extends OptionalClass = never> = {
  resource: Resource<Subject>;
};

type Props = {
  subject: string;
  websiteVersion?: string;
};

/**
 * Renders a Resource and all its Properties. Title
 * is rendered prominently at the top. If the Resource has a
 * particular Class, it will render a different Component.
 */
const ResourcePage: React.FC<Props> = ({ subject, websiteVersion }) => {
  const resource = useResource(subject);
  const { getPluginForClass, loading } = useCustomViews();
  const [isAList] = useArray(resource, core.properties.isA);
  const isA = isAList[0];
  const isPlugin = useIsPlugin(resource);
  const store = useStore();
  const drive = store.getDrive();
  const appClass = useAppClass(drive);
  const websiteClass = useWebsiteClass(isAList.join('|'));
  const websiteExportClass = useWebsiteClass(
    isAList.join('|'),
    'website-export',
  );

  // The body can have an inert attribute when the user navigated from an open dialog.
  // we remove it to make the page interactive again.
  useEffect(() => {
    document.body.removeAttribute('inert');
  }, []);

  // Guard against stuck `loading=true` placeholders. If the request orphans
  // (e.g. the server responds under a different normalized subject), the
  // `.loading` flag stays true forever. Surface a real error after 15s so the
  // user isn't staring at a spinner indefinitely.
  const [loadingExceeded, setLoadingExceeded] = useState(false);

  useEffect(() => {
    if (!resource.loading) {
      setLoadingExceeded(false);

      return;
    }

    const id = setTimeout(() => setLoadingExceeded(true), 15000);

    return () => clearTimeout(id);
  }, [resource.loading, subject]);

  // Once a subject has rendered its real view, a later `loading` flip (a
  // background refetch of the SAME subject — e.g. a POST that touches its
  // own resource, like an invite accept) must not fall through to the
  // spinner branch below: that branch renders a different component at
  // this position, so React unmounts the live view and remounts it once
  // loading clears, losing all of its component state (in-flight promises'
  // closures now update a dead instance). Only show the spinner for a
  // subject that hasn't loaded yet; resets when `subject` changes so a
  // genuine navigation still gets its spinner.
  const [loadedSubject, setLoadedSubject] = useState<string | undefined>(
    undefined,
  );

  useEffect(() => {
    if (!resource.loading) {
      setLoadedSubject(subject);
    }
  }, [resource.loading, subject]);

  const hasLoadedThisSubject = loadedSubject === subject;

  if (resource.loading && !loadingExceeded && !hasLoadedThisSubject) {
    return (
      <Main subject={subject}>
        <Spinner centered />
      </Main>
    );
  }

  if (resource.loading && loadingExceeded) {
    return (
      <Main subject={subject}>
        <ContainerNarrow>
          <h2>Still loading…</h2>
          <p>
            The resource at <code>{subject}</code> hasn't loaded after 15
            seconds. It may not exist, or the server may be unreachable.
          </p>
          <p>Check the browser console for details, or try navigating back.</p>
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

  let ReturnComponent = selectComponent(isA);

  if (ReturnComponent === ResourcePageDefault) {
    if (loading) return null;

    if (
      (websiteClass && resource.hasClasses(websiteClass)) ||
      (websiteExportClass && resource.hasClasses(websiteExportClass))
    ) {
      return (
        <Main subject={subject}>
          <ErrorBoundary>
            <Suspense fallback={<Spinner centered />}>
              {websiteExportClass ? (
                <WebsiteExportPage resource={resource} />
              ) : (
                <>
                  {websiteVersion ? (
                    <WebsiteExportPage
                      resource={resource}
                      deployment={websiteVersion}
                    />
                  ) : (
                    <WebsitePage resource={resource} />
                  )}
                </>
              )}
            </Suspense>
          </ErrorBoundary>
        </Main>
      );
    }

    // Like a plugin's, an app's class is minted per drive, so it cannot be a
    // case in `selectComponent`. An app opens to its own view.
    if (appClass !== undefined && resource.hasClasses(appClass)) {
      return (
        <Main subject={subject}>
          <ErrorBoundary>
            <Suspense fallback={<Spinner centered />}>
              <AppPage resource={resource} />
            </Suspense>
          </ErrorBoundary>
        </Main>
      );
    }

    // A plugin's class is minted per drive, so it has no fixed subject and
    // cannot be a case in `selectComponent`. It gets a real page all the same.
    if (isPlugin) {
      return (
        <Main subject={subject}>
          <ErrorBoundary>
            <Suspense fallback={<Spinner centered />}>
              <AtomicPluginPage resource={resource} drive={drive!} />
            </Suspense>
          </ErrorBoundary>
        </Main>
      );
    }

    const plugin = getPluginForClass(isA);

    if (plugin) {
      return (
        <Main subject={subject}>
          <ErrorBoundary>
            <Suspense fallback={<Spinner centered />}>
              <PluginView resource={resource} plugin={plugin} />
            </Suspense>
          </ErrorBoundary>
        </Main>
      );
    }
  }

  return (
    <Main subject={subject}>
      <ErrorBoundary>
        <Suspense fallback={<Spinner centered />}>
          {/* A fork renders through its content class's own view, so the bar is
              the only thing telling you this is not the original. */}
          <ForkBar resource={resource} />
          {/* And on the original: the forks proposing changes to it. */}
          <PendingForks resource={resource} />
          <ImportResolutionNotice resource={resource} />
          <ReturnComponent resource={resource} />
        </Suspense>
      </ErrorBoundary>
    </Main>
  );
};

function selectComponent(klass: string | undefined) {
  switch (klass) {
    case collections.classes.collection:
      return Collection;
    case server.classes.endpoint:
      return EndpointPage;
    case server.classes.drive:
      return DrivePage;
    case server.classes.invite:
    case server.classes.redirect:
      return InvitePage;
    case dataBrowser.classes.document:
      return DocumentPage;
    case core.classes.class:
      return ClassPage;
    case server.classes.file:
      return FilePage;
    case dataBrowser.classes.chatroom:
      return ChatRoomPage;
    case conversations.classes.conversation:
      return ConversationPage;
    case dataBrowser.classes.message:
      return MessagePage;
    case dataBrowser.classes.chatLog:
      return ChatLogPage;
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
    case dataBrowser.classes.dashboard:
      return DashboardPage;
    case core.classes.ontology:
      return OntologyPage;
    case dataBrowser.classes.tag:
      return TagPage;
    case ai.classes.aiChat:
      return AIChatPage;
    case dataBrowser.classes.documentV2:
      return DocumentV2FullPage;
    case dataBrowser.classes.meeting:
      return MeetingPage;
    case canvas.classes.canvas:
      return CanvasPage;
    case forms.classes.form:
      return FormBuilderPage;
    case notifications.classes.inbox:
      return InboxPage;
    case server.classes.installation:
      return InstallationPage;
    default:
      return ResourcePageDefault;
  }
}

export default ResourcePage;
