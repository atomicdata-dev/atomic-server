import { forms, useArray, useString } from '@tomic/react';
import { useEffect, useId, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { ContainerFull } from '@components/Containers';
import { EditableTitle } from '@components/EditableTitle';
import { Row } from '@components/Row';
import type { ResourcePageProps } from '@views/ResourcePage';
import { PageTabBar } from './PageTabBar';
import { FieldList } from './FieldList';
import { FieldSettingsPanel } from './FieldSettingsPanel';
import { PublishToggle } from './PublishToggle';
import { FormPreviewButton } from './FormPreviewDialog';

export function FormBuilderPage({ resource }: ResourcePageProps): JSX.Element {
  const titleId = useId();
  const [pages] = useArray(resource, forms.properties.formPages);
  const [dataClassSubject] = useString(
    resource,
    forms.properties.formDataClass,
  );

  const [activePage, setActivePage] = useState<string | undefined>(pages[0]);
  const [selectedField, setSelectedField] = useState<string | undefined>();

  // Keep the active page valid as pages are added/removed/reordered.
  useEffect(() => {
    if (!activePage || !pages.includes(activePage)) {
      setActivePage(pages[0]);
    }
  }, [pages, activePage]);

  return (
    <ContainerFull>
      <FormBuilderGrid>
        <TitleSlot>
          <Row justify='space-between' center>
            <EditableTitle resource={resource} id={titleId} />
            <Row gap='0.5rem' center>
              <FormPreviewButton formSubject={resource.subject} />
              <PublishToggle resource={resource} />
            </Row>
          </Row>
        </TitleSlot>
        <MainSlot>
          {activePage && dataClassSubject && (
            <FieldList
              dataClassSubject={dataClassSubject}
              pageSubject={activePage}
              selectedField={selectedField}
              onSelectField={setSelectedField}
            />
          )}
        </MainSlot>
        <SettingsSlot>
          {selectedField && dataClassSubject && (
            <FieldSettingsPanel
              fieldSubject={selectedField}
              dataClassSubject={dataClassSubject}
            />
          )}
        </SettingsSlot>
        <PageBarSlot>
          <PageTabBar
            formResource={resource}
            activePage={activePage}
            onSelectPage={subject => {
              setActivePage(subject);
              setSelectedField(undefined);
            }}
          />
        </PageBarSlot>
      </FormBuilderGrid>
    </ContainerFull>
  );
}

const FormBuilderGrid = styled.div`
  display: grid;
  grid-template-areas: 'title title' 'main settings' 'pages pages';
  grid-template-columns: 1fr 18rem;
  grid-template-rows: 4rem auto min-content;
  width: 100%;
  min-height: ${p => p.theme.heights.fullPage};

  @container (max-width: 600px) {
    grid-template-areas: 'title' 'main' 'settings' 'pages';
    grid-template-columns: 100cqw;
    grid-template-rows: 4rem auto auto min-content;
  }
`;

const TitleSlot = styled.div`
  grid-area: title;
  padding: ${p => p.theme.size()};
`;

const MainSlot = styled.div`
  grid-area: main;
  padding: ${p => p.theme.size()};
`;

const SettingsSlot = styled.div`
  grid-area: settings;
  padding: ${p => p.theme.size()};
  border-left: 1px solid ${p => p.theme.colors.bg2};
`;

const PageBarSlot = styled.div`
  grid-area: pages;
  padding: ${p => p.theme.size()};
  border-top: 1px solid ${p => p.theme.colors.bg2};
  min-width: 0;
`;
