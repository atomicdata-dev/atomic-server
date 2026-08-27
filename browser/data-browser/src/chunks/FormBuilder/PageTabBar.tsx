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
import { FaCodeBranch, FaGripVertical, FaPlus } from 'react-icons/fa6';
import { Row } from '@components/Row';
import { ScrollArea } from '@components/ScrollArea';
import { SkeletonButton } from '@components/SkeletonButton';
import { ReorderableList, type ItemDragProps } from './ReorderableList';

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
          handle='custom'
          renderItem={(subject, _index, drag) => (
            <PageTab
              subject={subject}
              active={subject === activePage}
              drag={drag}
              onSelect={() => onSelectPage(subject)}
            />
          )}
        />
      </TabScrollArea>
      <AddButton type='button' onClick={addPage}>
        <FaPlus /> Add page
      </AddButton>
    </TabBarRow>
  );
}

interface PageTabProps {
  subject: string;
  active: boolean;
  drag: ItemDragProps;
  onSelect: () => void;
}

function PageTab({
  subject,
  active,
  drag,
  onSelect,
}: PageTabProps): JSX.Element {
  const resource = useResource(subject);
  const [name, setName] = useTitle(resource, Infinity, { commit: true });
  const [conditions] = useArray(resource, forms.properties.formConditions);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(name);

  const stopEditing = () => {
    const trimmed = draft.trim();

    if (trimmed && trimmed !== name) {
      setName(trimmed);
    }

    setEditing(false);
  };

  return (
    <TabChip $active={active} {...(editing ? {} : drag.itemProps)}>
      <Grip
        {...drag.handleProps}
        type='button'
        title='Move item'
        $active={active}
      >
        <FaGripVertical />
      </Grip>
      {conditions.length > 0 && <BranchIcon title='Conditional' />}
      {editing ? (
        // Rendered inside the tab and sized by a hidden copy of the text in
        // the label's own font, so entering edit mode leaves the tab exactly
        // the width it already was and the neighbouring tabs never shift.
        <TabEditor>
          <EditorSizer $active={active}>{draft || ' '}</EditorSizer>
          <TabInput
            autoFocus
            size={1}
            value={draft}
            $active={active}
            onChange={e => setDraft(e.target.value)}
            onBlur={stopEditing}
            onKeyDown={e => {
              if (e.key === 'Enter') {
                (e.target as HTMLInputElement).blur();
              } else if (e.key === 'Escape') {
                setDraft(name);
                setEditing(false);
              }
            }}
          />
        </TabEditor>
      ) : (
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
      )}
    </TabChip>
  );
}

const TabBarRow = styled(Row)`
  width: 100%;
  min-width: 0;
`;

/**
 * The horizontal scrollbar overlays the tabs, so it only shows on hover. The
 * mask fades out the right edge, so a tab scrolled half out of view reads as
 * "there is more" rather than as clipped.
 */
const TabScrollArea = styled(ScrollArea)`
  flex: 1;
  min-width: 0;
  padding-bottom: 0.4rem;
  mask-image: linear-gradient(
    to right,
    #000 calc(100% - 1.25rem),
    transparent 100%
  );
`;

const TabChip = styled.div<{ $active: boolean }>`
  display: flex;
  align-items: center;
  flex-shrink: 0;
  padding-left: 0.25rem;
  white-space: nowrap;
  border-radius: ${p => p.theme.radius};
  background-color: ${p => (p.$active ? p.theme.colors.bg1 : 'transparent')};
  transition: background-color ${p => p.theme.animation.duration} ease-out;

  &:hover {
    background-color: ${p => p.theme.colors.bg1};
  }
`;

/**
 * Reserved gutter, not a hover-inserted element: the grip always takes up its
 * space and only fades in, so hovering a tab never changes its width.
 */
const Grip = styled.button<{ $active: boolean }>`
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 0.85rem;
  padding: 0;
  margin: 0;
  appearance: none;
  border: none;
  background: transparent;
  cursor: grab;
  opacity: ${p => (p.$active ? 1 : 0)};
  transition: opacity ${p => p.theme.animation.duration} ease-out;

  &:active {
    cursor: grabbing;
  }

  svg {
    font-size: 0.7rem;
    color: ${p => p.theme.colors.textLight2};
  }

  ${TabChip}:hover &,
  &:focus-visible {
    opacity: 1;
  }

  &:hover svg {
    color: ${p => p.theme.colors.textLight};
  }
`;

const TabButton = styled.button<{ $active: boolean }>`
  display: inline-flex;
  align-items: center;
  padding: 0.35rem 0.6rem 0.35rem 0.2rem;
  border: none;
  background: none;
  color: ${p => (p.$active ? p.theme.colors.text : p.theme.colors.textLight)};
  font-weight: ${p => (p.$active ? 'bold' : 'normal')};
  font-size: inherit;
  cursor: pointer;
  white-space: nowrap;

  &:hover {
    color: ${p => p.theme.colors.text};
  }
`;

/** Overlays the input on a hidden copy of the text, which sets the width. */
const TabEditor = styled.span`
  display: inline-grid;
  align-items: center;
  padding: 0.35rem 0.6rem 0.35rem 0.2rem;
`;

const EditorSizer = styled.span<{ $active: boolean }>`
  grid-area: 1 / 1;
  min-width: 4ch;
  white-space: pre;
  visibility: hidden;
  font-weight: ${p => (p.$active ? 'bold' : 'normal')};
`;

const TabInput = styled.input<{ $active: boolean }>`
  grid-area: 1 / 1;
  width: 100%;
  min-width: 0;
  padding: 0;
  border: none;
  background: none;
  color: ${p => p.theme.colors.text};
  font: inherit;
  font-weight: ${p => (p.$active ? 'bold' : 'normal')};

  &:focus {
    outline: none;
  }
`;

const BranchIcon = styled(FaCodeBranch)`
  flex-shrink: 0;
  margin-left: 0.2rem;
  font-size: 0.75em;
  color: ${p => p.theme.colors.textLight};
`;

const AddButton = styled(SkeletonButton)`
  flex-shrink: 0;
  padding: 0.3rem 0.75rem;
`;
