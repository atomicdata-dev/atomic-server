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
import type { ResourcePageProps } from '@views/ResourcePage';
import { PageTabBar } from './PageTabBar';
import { FieldList } from './FieldList';
import { FieldSettingsPanel } from './FieldSettingsPanel';
import { PageSettingsPanel } from './PageSettingsPanel';
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
        <HeaderRow>
          <TitleArea>
            <EditableTitle resource={resource} id={titleId} />
          </TitleArea>
          <HeaderActions>
            <ShareLinkPanel resource={resource} />
            <FormPreviewButton formSubject={resource.subject} />
            <PublishToggle resource={resource} />
          </HeaderActions>
        </HeaderRow>
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
            {selectedField && dataClassSubject ? (
              <FieldSettingsPanel
                fieldSubject={selectedField}
                dataClassSubject={dataClassSubject}
                form={resource}
              />
            ) : (
              activePage && (
                <PageSettingsPanel pageSubject={activePage} form={resource} />
              )
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

/**
 * Title on the left, action buttons on the right. The title is the only part
 * allowed to wrap: `Button` wraps its label by default (phones), which turned
 * "Unpublish" into three stacked characters as soon as the header got tight —
 * with the AI chat open, or on anything narrower than a full-screen laptop.
 *
 * So the actions keep their intrinsic width and the title takes the squeeze
 * first. Once the title is down to its own floor (`min-width` below) there is
 * nothing left to give, and the whole action group wraps onto a second line
 * instead. No breakpoint involved: the flow reacts to the space actually
 * available, so it works the same in a side panel as in the main view.
 */
const HeaderRow = styled.div`
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem ${p => p.theme.size()};
`;

const TitleArea = styled.div`
  /* Basis 0, so the title never asks for its full single-line width: it takes
     whatever the actions leave over and wraps inside it. With a basis of
     auto the actions dropped to a second line the moment the title stopped
     fitting on one, wasting a whole row on a header that had space left. */
  flex: 1 1 0;
  /* The floor at which the title stops shrinking and the actions wrap to
     their own line instead. Wide enough for a long-ish word at h1 size, so
     the squeeze wraps the title between words rather than through them.
     Capped at 100% so a container narrower than the floor still wraps
     instead of overflowing. */
  min-width: min(100%, 16rem);
`;

const HeaderActions = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  /* Stay on one line and at intrinsic width: these are the items that must
     not be squeezed. */
  flex-wrap: nowrap;
  flex-shrink: 0;

  button {
    white-space: nowrap;
    overflow-wrap: normal;
  }
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
  grid-template-columns: 1fr 25rem;
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
