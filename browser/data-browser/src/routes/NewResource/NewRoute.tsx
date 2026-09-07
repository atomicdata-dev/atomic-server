import { useResource, core } from '@tomic/react';
import { Fragment, useCallback, type JSX } from 'react';

import { constructOpenURL } from '../../helpers/navigation';
import {
  ContainerFull,
  ContainerNarrow,
  ContainerWide,
} from '../../components/Containers';
import { ResourceSelector } from '../../components/forms/ResourceSelector';
import { useSettings } from '../../helpers/AppSettings';
import { ResourceInline } from '../../views/ResourceInline';
import { styled } from 'styled-components';
import { FileDropzoneInput } from '../../components/forms/FileDropzone/FileDropzoneInput';
import toast from 'react-hot-toast';
import { NewFormFullPage } from '../../components/forms/NewForm/NewFormPage';
import { Main } from '../../components/Main';
import { BaseButtons } from './BaseButtons';
import { OntologySections } from './OntologySections';
import { useNewResourceUI } from '../../components/forms/NewForm/useNewResourceUI';
import { Column } from '../../components/Row';
import { TemplateList } from '../../components/Template/TemplateList';
import { useNavigateWithTransition } from '../../hooks/useNavigateWithTransition';
import { pathNames } from '../paths';
import { createRoute } from '@tanstack/react-router';
import { appRoute } from '../RootRoutes';

export interface NewRouteSearchParams {
  classSubject: string | undefined;
  parent: string | undefined;
  parentSubject: string | undefined;
  newSubject: string | undefined;
}

export const NewRoute = createRoute({
  path: pathNames.new,
  component: () => <NewRoutePage />,
  getParentRoute: () => appRoute,
  validateSearch: (search: Record<string, unknown>): NewRouteSearchParams => ({
    classSubject: (search.classSubject as string) ?? undefined,
    parent: (search.parent as string) ?? undefined,
    parentSubject: (search.parentSubject as string) ?? undefined,
    newSubject: (search.newSubject as string) ?? undefined,
  }),
});

/** Start page for instantiating a new Resource from some Class */
function NewRoutePage(): JSX.Element {
  const { classSubject } = NewRoute.useSearch();

  return (
    <Main>
      {classSubject ? (
        <ContainerNarrow>
          <NewFormFullPage classSubject={classSubject.toString()} />
        </ContainerNarrow>
      ) : (
        <ContainerFull>
          <NewResourceSelector />
        </ContainerFull>
      )}
    </Main>
  );
}

function NewResourceSelector() {
  const { parentSubject } = NewRoute.useSearch();
  const { drive, hideTemplates } = useSettings();
  const calculatedParent = parentSubject || drive;
  const parentResource = useResource(calculatedParent);

  const showTemplates = !hideTemplates && calculatedParent === drive;
  const Container = showTemplates ? ContainerWide : ContainerNarrow;

  const navigate = useNavigateWithTransition();
  const showNewResourceUI = useNewResourceUI();

  function handleClassSet(subject: string | undefined) {
    if (!subject) {
      return;
    }

    showNewResourceUI(subject, calculatedParent);
  }

  const onUploadComplete = useCallback(
    (files: string[]) => {
      toast.success(`Uploaded ${files.length} files.`);

      // Single file → open it directly so the user can verify the preview
      // and download work. Multi-upload → fall back to the parent listing
      // since opening N tabs would be hostile.
      if (files.length === 1) {
        navigate(constructOpenURL(files[0]));

        return;
      }

      if (calculatedParent) {
        navigate(constructOpenURL(calculatedParent));
      }
    },
    [calculatedParent, navigate],
  );

  return (
    <Container>
      <Column gap='2rem'>
        <h1>
          <span>Create new resource</span>{' '}
          {calculatedParent && (
            <>
              <span>under</span>
              <ResourceInline subject={calculatedParent} />
            </>
          )}
        </h1>
        <SideBySide noTemplates={!showTemplates}>
          <Column gap='2rem'>
            <div>
              <ResourceSelector
                hideCreateOption
                setSubject={handleClassSet}
                isA={core.classes.class}
              />
            </div>
            <BaseButtons parent={calculatedParent} />
            <OntologySections parent={calculatedParent} />
            <FileDropzoneInput
              parentResource={parentResource}
              onFilesUploaded={onUploadComplete}
            />
          </Column>
          {showTemplates && (
            <Fragment key='templates'>
              <Devider />
              <Column>
                <h2>Templates</h2>
                <TemplateList />
              </Column>
            </Fragment>
          )}
        </SideBySide>
      </Column>
    </Container>
  );
}

const SideBySide = styled.div<{ noTemplates: boolean }>`
  display: grid;
  grid-template-columns: ${p => (p.noTemplates ? '1fr' : '2.5fr 1px 1fr')};
  gap: 2rem;

  @container (max-width: 700px) {
    grid-template-columns: 1fr;
  }
`;

const Devider = styled.div`
  border-right: 1px solid ${p => p.theme.colors.bg2};
`;
