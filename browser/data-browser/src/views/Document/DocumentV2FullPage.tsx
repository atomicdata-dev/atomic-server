import { EditableTitle } from '@components/EditableTitle';
import { ResourceCoverImage } from '@components/ResourceDecorations';
import { dataBrowser, useLoroDoc, useLoroReady, useStore } from '@tomic/react';
import type { ResourcePageProps } from '@views/ResourcePage';
import { lazy, Suspense, useEffect, useState } from 'react';
import styled from 'styled-components';
import {
  useCustomContextItems,
  DIVIDER,
} from '@components/ResourceContextMenu';
import { FaFilePdf } from 'react-icons/fa6';
import {
  isYjsMigrationCandidate,
  loroDocHasVisibleContent,
  upgradeDocument,
} from './upgradeDocument';
import { Spinner } from '../../components/Spinner';

const CollaborativeEditor = lazy(
  () => import('@chunks/RTE/CollaborativeEditor'),
);

const customMenuItems = [
  DIVIDER,
  {
    id: 'print-document',
    label: 'Export to PDF',
    helper: 'Print this document to a PDF file',
    icon: <FaFilePdf />,
    onClick: () => window.print(),
  },
];

export const DocumentV2FullPage: React.FC<ResourcePageProps> = ({
  resource,
}) => {
  const store = useStore();
  const doc = useLoroDoc(resource);
  const loroReady = useLoroReady();

  useCustomContextItems(customMenuItems);

  // `useLoroDoc` returns undefined while the Loro CRDT WASM module is
  // still streaming in (transient) OR when it failed to load entirely
  // (terminal — `enableLoro()` in App.tsx only `console.warn`s on
  // failure). Without distinguishing them, a tab where Loro never
  // loaded sits on "Loading..." forever with no signal. Give the WASM
  // import a bounded grace window, then surface a real error.
  const [graceExpired, setGraceExpired] = useState(false);
  const leftoverYjs = isYjsMigrationCandidate(
    resource.get(dataBrowser.properties.documentContent),
    doc ? !loroDocHasVisibleContent(doc) : true,
  );
  const [yjsMigrated, setYjsMigrated] = useState(!leftoverYjs);

  useEffect(() => {
    if (doc || loroReady) {
      setGraceExpired(false);

      return;
    }

    const id = setTimeout(() => setGraceExpired(true), 8000);

    return () => clearTimeout(id);
  }, [doc, loroReady]);

  useEffect(() => {
    if (!leftoverYjs || !doc) {
      return;
    }

    let cancelled = false;

    upgradeDocument(resource, store)
      .catch(error => {
        console.error(
          '[upgradeDocument] Yjs leftover migration failed:',
          error,
        );
      })
      .finally(() => {
        if (!cancelled) {
          setYjsMigrated(true);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [doc, leftoverYjs, resource, store]);

  if (!doc) {
    // Loro is ready (or gave up) but we still have no doc → the editor
    // engine isn't available. Show why instead of an endless spinner.
    if (loroReady || graceExpired) {
      return (
        <ErrorWrapper role='alert'>
          <h2>Couldn&apos;t open the document editor</h2>
          <p>
            The collaborative editing engine (Loro / WebAssembly) failed to
            initialize in this tab, so the document body can&apos;t be shown.
          </p>
          <p>
            Try reloading the page. If it keeps happening, another tab of this
            app or a browser extension may be blocking WebAssembly, or the tab
            ran out of memory.
          </p>
        </ErrorWrapper>
      );
    }

    return <Spinner centered />;
  }

  if (!yjsMigrated) {
    return <Spinner centered />;
  }

  const focusEditor = () => {
    document.getElementById('document-editor')?.focus();
  };

  return (
    <FullPageWrapper>
      <ResourceCoverImage resource={resource} />
      <DocumentContainer>
        <EditableTitle
          resource={resource}
          onCommit={focusEditor}
          withDecorations
        />

        <Suspense fallback={<Spinner centered />}>
          <CollaborativeEditor
            id='document-editor'
            resource={resource}
            doc={doc}
            property={dataBrowser.properties.documentContent}
            toolbar
          />
        </Suspense>
      </DocumentContainer>
    </FullPageWrapper>
  );
};

const ErrorWrapper = styled.div`
  width: min(100%, ${p => p.theme.containerWidthWide});
  margin: auto;
  padding: ${p => p.theme.size(7)};
  color: ${p => p.theme.colors.textLight};
  h2 {
    color: ${p => p.theme.colors.alert};
  }
`;

const FullPageWrapper = styled.div`
  background-color: ${p => p.theme.colors.bg};
  display: flex;
  flex: 1;
  flex-direction: column;
  min-height: ${p => p.theme.heights.fullPage};
  box-sizing: border-box;
  @media print {
    min-height: 100vh;
  }
`;

const DocumentContainer = styled.div`
  width: min(100%, ${p => p.theme.containerWidthWide});
  margin: auto;
  display: flex;
  gap: ${p => p.theme.size()};
  flex: 1;
  flex-direction: column;
  padding: ${p => p.theme.size(7)};
  h1 {
    margin-bottom: 0;
  }
  @media (max-width: ${props => props.theme.containerWidthWide}) {
    padding: ${p => p.theme.size()};
  }
`;
