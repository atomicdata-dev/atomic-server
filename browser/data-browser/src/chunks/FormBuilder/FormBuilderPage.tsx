import {
  forms,
  unknownSubject,
  useArray,
  useResource,
  useString,
} from '@tomic/react';
import { useEffect, useId, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { EditableTitle } from '@components/EditableTitle';
import { Row } from '@components/Row';
import type { ResourcePageProps } from '@views/ResourcePage';
import { PageTabBar } from './PageTabBar';
import { FieldList } from './FieldList';
import { FieldSettingsPanel } from './FieldSettingsPanel';
import { PublishToggle } from './PublishToggle';
import { FormPreviewButton } from './FormPreviewDialog';
import { ResultsTab } from './ResultsTab';
import { ShareLinkPanel } from './ShareLinkPanel';
import { SummaryTab } from './Summary/SummaryTab';
import { SettingsTab } from './SettingsTab';

type BuilderTab = 'fields' | 'results' | 'summary' | 'settings';

export function FormBuilderPage({ resource }: ResourcePageProps): JSX.Element {
  const titleId = useId();
  const [pages] = useArray(resource, forms.properties.formPages);
  const [dataClassSubject] = useString(
    resource,
    forms.properties.formDataClass,
  );
  const [tableSubject] = useString(resource, forms.properties.formTargetTable);
  const tableResource = useResource(tableSubject ?? unknownSubject);

  const [activeTab, setActiveTab] = useState<BuilderTab>('fields');
  const [activePage, setActivePage] = useState<string | undefined>(pages[0]);
  const [selectedField, setSelectedField] = useState<string | undefined>();

  // Keep the active page valid as pages are added/removed/reordered.
  useEffect(() => {
    if (!activePage || !pages.includes(activePage)) {
      setActivePage(pages[0]);
    }
  }, [pages, activePage]);

  return (
    <Shell>
      <TitleSlot>
        <Row justify='space-between' center>
          <EditableTitle resource={resource} id={titleId} />
          <Row gap='0.5rem' center>
            <ShareLinkPanel resource={resource} />
            <FormPreviewButton formSubject={resource.subject} />
            <PublishToggle resource={resource} />
          </Row>
        </Row>
      </TitleSlot>
      <TabsSlot role='tablist'>
        <TabButton
          role='tab'
          type='button'
          $active={activeTab === 'fields'}
          aria-selected={activeTab === 'fields'}
          onClick={() => setActiveTab('fields')}
        >
          Fields
        </TabButton>
        <TabButton
          role='tab'
          type='button'
          $active={activeTab === 'settings'}
          aria-selected={activeTab === 'settings'}
          onClick={() => setActiveTab('settings')}
        >
          Settings
        </TabButton>
        <TabButton
          role='tab'
          type='button'
          $active={activeTab === 'results'}
          aria-selected={activeTab === 'results'}
          onClick={() => setActiveTab('results')}
        >
          Results
        </TabButton>
        <TabButton
          role='tab'
          type='button'
          $active={activeTab === 'summary'}
          aria-selected={activeTab === 'summary'}
          onClick={() => setActiveTab('summary')}
        >
          Summary
        </TabButton>
      </TabsSlot>
      {activeTab === 'fields' ? (
        <FieldsGrid>
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
        </FieldsGrid>
      ) : activeTab === 'settings' ? (
        <ResultsSlot>
          <SettingsTab resource={resource} />
        </ResultsSlot>
      ) : activeTab === 'results' ? (
        <ResultsSlot>
          <ResultsTab tableResource={tableResource} />
        </ResultsSlot>
      ) : (
        <ResultsSlot>
          <SummaryTab formSubject={resource.subject} />
        </ResultsSlot>
      )}
    </Shell>
  );
}

const Shell = styled.div`
  height: ${p => p.theme.heights.fullPage};
  overflow: hidden;
  padding-bottom: 0;
  display: flex;
  flex-direction: column;

  @container (max-width: 600px) {
    height: auto;
    overflow: visible;
    padding-bottom: 10rem;
  }
`;

const TitleSlot = styled.div`
  flex-shrink: 0;
  padding: ${p => p.theme.size()};
`;

const TabsSlot = styled.div`
  flex-shrink: 0;
  display: flex;
  gap: 0.25rem;
  padding-inline: ${p => p.theme.size()};
  border-bottom: 1px solid ${p => p.theme.colors.bg2};
`;

const TabButton = styled.button<{ $active: boolean }>`
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  height: 2.2rem;
  padding: 0 0.8rem;
  border: none;
  border-bottom: 2px solid
    ${p => (p.$active ? p.theme.colors.main : 'transparent')};
  background: none;
  color: ${p => (p.$active ? p.theme.colors.text : p.theme.colors.textLight)};
  font-weight: ${p => (p.$active ? 'bold' : 'normal')};
  cursor: pointer;

  &:hover {
    color: ${p => p.theme.colors.text};
  }
`;

const FieldsGrid = styled.div`
  display: grid;
  grid-template-areas: 'main settings' 'pages pages';
  grid-template-columns: 1fr 18rem;
  grid-template-rows: 1fr min-content;
  flex: 1;
  min-height: 0;
  width: 100%;

  @container (max-width: 600px) {
    grid-template-areas: 'main' 'settings' 'pages';
    grid-template-columns: 100cqw;
    grid-template-rows: auto auto min-content;
    height: auto;
  }
`;

const MainSlot = styled.div`
  grid-area: main;
  padding: ${p => p.theme.size()};
  min-height: 0;
  overflow-y: auto;
`;

const SettingsSlot = styled.div`
  grid-area: settings;
  padding: ${p => p.theme.size()};
  border-left: 1px solid ${p => p.theme.colors.bg2};
  min-height: 0;
  overflow-y: auto;
`;

const PageBarSlot = styled.div`
  grid-area: pages;
  padding: ${p => p.theme.size()};
  border-top: 1px solid ${p => p.theme.colors.bg2};
  min-width: 0;
  position: sticky;
  bottom: 0;
  background-color: ${p => p.theme.colors.bg};
`;

const ResultsSlot = styled.div`
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  padding: ${p => p.theme.size()};
`;
