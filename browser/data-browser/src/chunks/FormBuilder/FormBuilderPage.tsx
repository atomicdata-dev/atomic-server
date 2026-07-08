import { forms, useArray, useString } from '@tomic/react';
import { useEffect, useId, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { ContainerFull } from '@components/Containers';
import { EditableTitle } from '@components/EditableTitle';
import { Row } from '@components/Row';
import type { ResourcePageProps } from '@views/ResourcePage';
import { PageSidebar } from './PageSidebar';
import { FieldList } from './FieldList';
import { FieldSettingsPanel } from './FieldSettingsPanel';
import { PublishToggle } from './PublishToggle';

export function FormBuilderPage({ resource }: ResourcePageProps): JSX.Element {
  const titleId = useId();
  const [pages] = useArray(resource, forms.properties.formPages);
  const [dataClassSubject] = useString(resource, forms.properties.formDataClass);

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
            <PublishToggle resource={resource} />
          </Row>
        </TitleSlot>
        <SidebarSlot>
          <PageSidebar
            formResource={resource}
            activePage={activePage}
            onSelectPage={subject => {
              setActivePage(subject);
              setSelectedField(undefined);
            }}
          />
        </SidebarSlot>
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
      </FormBuilderGrid>
    </ContainerFull>
  );
}

const FormBuilderGrid = styled.div`
  display: grid;
  grid-template-areas: 'title title title' 'sidebar main settings';
  grid-template-columns: 14rem 1fr 18rem;
  grid-template-rows: 4rem auto;
  width: 100%;
  min-height: ${p => p.theme.heights.fullPage};

  @container (max-width: 900px) {
    grid-template-areas: 'title title' 'sidebar main' 'settings settings';
    grid-template-columns: 14rem 1fr;
    grid-template-rows: 4rem auto auto;
  }

  @container (max-width: 600px) {
    grid-template-areas: 'title' 'sidebar' 'main' 'settings';
    grid-template-columns: 100cqw;
    grid-template-rows: 4rem auto auto auto;
  }
`;

const TitleSlot = styled.div`
  grid-area: title;
  padding: ${p => p.theme.size()};
`;

const SidebarSlot = styled.div`
  grid-area: sidebar;
  padding: ${p => p.theme.size()};
  border-right: 1px solid ${p => p.theme.colors.bg2};
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
