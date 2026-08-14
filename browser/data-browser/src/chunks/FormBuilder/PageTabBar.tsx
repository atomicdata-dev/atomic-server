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
import { FaPlus, FaTrash } from 'react-icons/fa6';
import { Row } from '@components/Row';
import { Button } from '@components/Button';
import { InputStyled } from '@components/forms/InputStyles';
import {
  IconButton,
  IconButtonVariant,
} from '@components/IconButton/IconButton';
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
    setPages([...pages, page.subject]);
    onSelectPage(page.subject);
  };

  const deletePage = async (subject: string) => {
    if (pages.length <= 1) {
      return;
    }

    const page = await store.getResource(subject);
    const conditions =
      (page.get(forms.properties.formConditions) as string[] | undefined) ?? [];

    for (const condSubject of conditions) {
      const cond = await store.getResource(condSubject);
      await cond.destroy();
    }

    setPages(pages.filter(p => p !== subject));
    await page.destroy();

    if (activePage === subject) {
      const remaining = pages.filter(p => p !== subject);
      onSelectPage(remaining[0]);
    }
  };

  return (
    <TabBarRow gap='0.5rem' center>
      <ScrollArea>
        <ReorderableList
          subjects={pages}
          onReorder={setPages}
          orientation='horizontal'
          renderItem={subject => (
            <PageTab
              subject={subject}
              active={subject === activePage}
              canDelete={pages.length > 1}
              onSelect={() => onSelectPage(subject)}
              onDelete={() => deletePage(subject)}
            />
          )}
        />
      </ScrollArea>
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
  canDelete: boolean;
  onSelect: () => void;
  onDelete: () => void;
}

function PageTab({
  subject,
  active,
  canDelete,
  onSelect,
  onDelete,
}: PageTabProps): JSX.Element {
  const resource = useResource(subject);
  const [name, setName] = useTitle(resource, Infinity, { commit: true });
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
        onClick={onSelect}
        onDoubleClick={() => {
          setDraft(name);
          setEditing(true);
        }}
      >
        {name || 'Untitled page'}
      </TabButton>
      {canDelete && (
        <IconButton
          variant={IconButtonVariant.Simple}
          size='0.8rem'
          color='textLight'
          title='Delete page'
          type='button'
          onClick={onDelete}
        >
          <FaTrash />
        </IconButton>
      )}
    </TabRow>
  );
}

const TabBarRow = styled(Row)`
  width: 100%;
  min-width: 0;
`;

const ScrollArea = styled.div`
  flex: 1;
  min-width: 0;
  overflow-x: auto;
  overflow-y: hidden;
`;

const TabRow = styled(Row)<{ $active: boolean }>`
  align-items: center;
  gap: 0.25rem;
  flex-shrink: 0;
  white-space: nowrap;
`;

const TabButton = styled.button<{ $active: boolean }>`
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

const AddButton = styled(Button)`
  flex-shrink: 0;
  box-shadow: none;
  border: 1px dashed ${p => p.theme.colors.bg2};
  background: none;
`;
