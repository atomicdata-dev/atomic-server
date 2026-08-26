import {
  core,
  forms,
  Resource,
  useArray,
  useResource,
  useStore,
  useTitle,
} from '@tomic/react';
import { useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { FaCodeBranch, FaPlus } from 'react-icons/fa6';
import { Row } from '@components/Row';
import { Button } from '@components/Button';
import { InputStyled } from '@components/forms/InputStyles';
import { ScrollArea } from '@components/ScrollArea';
import { ReorderableList } from './ReorderableList';

interface PageTabBarProps {
  formResource: Resource;
  activePage: string | undefined;
  onSelectPage: (subject: string) => void;
}

export function PageTabBar({
  formResource,
  activePage,
  onSelectPage,
}: PageTabBarProps): JSX.Element {
  const store = useStore();
  const [pages, setPages] = useArray(formResource, forms.properties.formPages, {
    commit: true,
  });

  const addPage = async () => {
    const page = await store.newResource({
      parent: formResource.subject,
      isA: forms.classes.formPage,
      propVals: {
        [core.properties.name]: `Page ${pages.length + 1}`,
        [forms.properties.formFields]: [],
      },
    });
    await page.save();
    // Write the form's page list explicitly and await durability — the
    // debounced `setPages` commit is fire-and-forget, and if it never lands
    // the page just saved above is orphaned (exists, but no form points at
    // it).
    await formResource.set(forms.properties.formPages, [
      ...pages,
      page.subject,
    ]);
    await formResource.save();
    onSelectPage(page.subject);
  };

  return (
    <TabBarRow gap='0.5rem' center>
      <TabScrollArea type='hover'>
        <ReorderableList
          subjects={pages}
          onReorder={setPages}
          orientation='horizontal'
          renderItem={subject => (
            <PageTab
              subject={subject}
              active={subject === activePage}
              onSelect={() => onSelectPage(subject)}
            />
          )}
        />
      </TabScrollArea>
      <AddButton type='button' subtle onClick={addPage}>
        <Row gap='.5rem' center>
          <FaPlus /> Add page
        </Row>
      </AddButton>
    </TabBarRow>
  );
}

interface PageTabProps {
  subject: string;
  active: boolean;
  onSelect: () => void;
}

function PageTab({ subject, active, onSelect }: PageTabProps): JSX.Element {
  const resource = useResource(subject);
  const [name, setName] = useTitle(resource, Infinity, { commit: true });
  const [conditions] = useArray(resource, forms.properties.formConditions);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(name);

  if (editing) {
    return (
      <InputStyled
        autoFocus
        value={draft}
        onChange={e => setDraft(e.target.value)}
        onBlur={() => {
          const trimmed = draft.trim();

          if (trimmed && trimmed !== name) {
            setName(trimmed);
          }

          setEditing(false);
        }}
        onKeyDown={e => {
          if (e.key === 'Enter') {
            (e.target as HTMLInputElement).blur();
          } else if (e.key === 'Escape') {
            setDraft(name);
            setEditing(false);
          }
        }}
      />
    );
  }

  return (
    <TabRow $active={active}>
      <TabButton
        type='button'
        $active={active}
        title={conditions.length > 0 ? 'Conditional' : undefined}
        onClick={onSelect}
        onDoubleClick={() => {
          setDraft(name);
          setEditing(true);
        }}
      >
        {conditions.length > 0 && <BranchIcon aria-hidden />}
        {name || 'Untitled page'}
      </TabButton>
    </TabRow>
  );
}

const TabBarRow = styled(Row)`
  width: 100%;
  min-width: 0;
`;

/** The horizontal scrollbar overlays the tabs, so it only shows on hover. */
const TabScrollArea = styled(ScrollArea)`
  flex: 1;
  min-width: 0;
  padding-bottom: 0.4rem;
`;

const TabRow = styled(Row)<{ $active: boolean }>`
  align-items: center;
  gap: 0.25rem;
  flex-shrink: 0;
  white-space: nowrap;
`;

const TabButton = styled.button<{ $active: boolean }>`
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  text-align: left;
  padding: 0.35rem 0.6rem;
  border: none;
  border-radius: ${p => p.theme.radius};
  background-color: ${p => (p.$active ? p.theme.colors.bg1 : 'transparent')};
  color: ${p => (p.$active ? p.theme.colors.text : p.theme.colors.textLight)};
  font-weight: ${p => (p.$active ? 'bold' : 'normal')};
  cursor: pointer;
  white-space: nowrap;

  &:hover {
    background-color: ${p => p.theme.colors.bg1};
  }
`;

const BranchIcon = styled(FaCodeBranch)`
  flex-shrink: 0;
  font-size: 0.75em;
  color: ${p => p.theme.colors.textLight};
`;

const AddButton = styled(Button)`
  flex-shrink: 0;
  box-shadow: none;
  border: 1px dashed ${p => p.theme.colors.bg2};
  background: none;
`;
