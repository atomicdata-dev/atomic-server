import * as React from 'react';
import { styled } from 'styled-components';
import { useHotkeys } from 'react-hotkeys-hook';
import {
  useArray,
  useNumber,
  useResource,
  useResources,
  useString,
  useStore,
  properties,
} from '@tomic/react';
import {
  FaArrowLeft,
  FaArrowRight,
  FaInfo,
  FaTable,
  FaTableCellsLarge,
} from 'react-icons/fa6';

import { useViewport } from '../helpers/useMedia';
import { Button } from '../components/Button';
import { ContainerFull } from '../components/Containers';
import Markdown from '../components/datatypes/Markdown';
import { NewInstanceButton } from '../components/NewInstanceButton';
import ResourceCard from './Card/ResourceCard';
import Table from '../components/Table';
import { useSubjectParam } from '../helpers/useCurrentSubject';
import { ComboBox, type ComboBoxOption } from '../components/ComboBox';
import { AtomicLink } from '../components/AtomicLink';
import { ResourcePageProps } from './ResourcePage';
import { useEffectOnce } from '../hooks/useEffectOnce';
import { Row } from '../components/Row';
import { EditableTitle } from '../components/EditableTitle';
import { useLocalStorage } from '../hooks/useLocalStorage';

import type { JSX } from 'react';

const displayStyles = [
  {
    id: 'cards',
    icon: <FaTableCellsLarge />,
  },
  {
    id: 'table',
    icon: <FaTable />,
  },
];

/** A View for collections. Contains logic for switching between various views. */
function Collection({ resource }: ResourcePageProps): JSX.Element {
  const [description] = useString(resource, properties.description);
  const viewportWidth = useViewport();
  // If a user is on a smaller screen, it's probably best to show a Cardlist
  const defaultView = viewportWidth < 700 ? 0 : 1;
  const [displayStyleIndex, setDisplayStyle] = useLocalStorage(
    'CollectionDisplayStyle',
    defaultView,
  );
  const [members] = useArray(resource, properties.collection.members);
  const [valueFilter] = useString(resource, properties.collection.value);
  const [propertyFilter] = useString(resource, properties.collection.property);
  // We use the currentPage and totalpages from the Collection Resource itself - not the query param. This gives us a default value.
  const [currentPageQueryParam] = useNumber(
    resource,
    properties.collection.currentPage,
  );
  const currentPage: number = currentPageQueryParam || 0;
  const [totalPagesQP] = useNumber(resource, properties.collection.totalPages);
  const totalPages: number = totalPagesQP || 1;

  // Query parameters for Collections
  const [, setPage] = useSubjectParam('current_page');
  const [sortBy, setSortBy] = useSubjectParam('sort_by');

  // We kind of assume here that all Collections will be filtered by an `is-a` prop and `Class` value.
  // But we can also have a collection of thing that share the same creator.
  // If that happens, we need a different approach to rendering the Headers
  const classResource = useResource(valueFilter);
  const [requiredProps] = useArray(classResource, properties.requires);
  const [recommendedProps] = useArray(classResource, properties.recommends);
  const propsArrayFull = requiredProps.concat(recommendedProps);

  // Info about the current Class
  const [classDescription] = useString(classResource, properties.description);
  const [classTitle] = useString(classResource, properties.shortname);
  const [showClassDescription, setShowClassDescription] = React.useState(false);

  const isClass = valueFilter && propertyFilter === properties.isA;

  const store = useStore();

  useEffectOnce(() => {
    // Always refresh the collection when opening this page.
    // We don't have cool collection invalidation yet.
    store.fetchResourceFromServer(resource.subject);
  });

  function handleToggleView() {
    setDisplayStyle(getNextDisplayStyleIndex());
  }

  function getNextDisplayStyleIndex() {
    let newIndex = displayStyleIndex + 1;

    if (newIndex >= displayStyles.length) {
      newIndex = 0;
    }

    return newIndex;
  }

  function handlePrevPage() {
    if (currentPage !== 0) {
      const nextNumber = currentPage - 1;
      setPage(nextNumber.toString());
    }
  }

  function handleNextPage() {
    if (currentPage !== totalPages - 1) {
      const nextNumber = currentPage + 1;
      setPage(nextNumber.toString());
    }
  }

  function handleSetSort(by: string | undefined) {
    setSortBy(by);
  }

  const displayStyle = displayStyles[displayStyleIndex];
  const nextDisplayStyle = displayStyles[getNextDisplayStyleIndex()];

  useHotkeys('right', handleNextPage, {}, [currentPage]);
  useHotkeys('left', handlePrevPage, {}, [currentPage]);

  const Pagination = () => (
    <Row>
      <Button
        subtle
        onClick={handlePrevPage}
        title='previous page (left arrow)'
        disabled={currentPage === 0}
      >
        <FaArrowLeft />
      </Button>
      <Button
        subtle
        onClick={handleNextPage}
        title='next page (right arrow)'
        disabled={currentPage === totalPages! - 1}
        data-test='next-page'
      >
        <FaArrowRight />
      </Button>
    </Row>
  );

  return (
    <ContainerFull>
      <EditableTitle resource={resource} />
      {description && <Markdown text={description} />}
      <ButtonsBar>
        {totalPages! > 1 && <Pagination />}
        <Button
          subtle
          onClick={handleToggleView}
          title={`use ${nextDisplayStyle.id} view (v)`}
        >
          {nextDisplayStyle.icon}
        </Button>
        {isClass && (
          <NewInstanceButton
            subtle
            icon
            klass={valueFilter}
            parent={resource.getSubjectNoParams()}
          />
        )}
        {isClass && (
          <Button
            subtle
            onClick={() => setShowClassDescription(!showClassDescription)}
            title={
              showClassDescription
                ? `Hide ${classTitle} info`
                : `Show ${classTitle} info`
            }
          >
            <FaInfo />
          </Button>
        )}
        {isClass && (
          <DropDownMini>
            <SortByPicker
              properties={propsArrayFull}
              selected={sortBy}
              onSelect={handleSetSort}
            />
          </DropDownMini>
        )}
      </ButtonsBar>
      {showClassDescription && valueFilter && (
        <>
          <AtomicLink subject={valueFilter}>
            <h3>{classTitle}</h3>
          </AtomicLink>
          <Markdown text={classDescription || ''} />
        </>
      )}
      {members.length === 0 ? (
        valueFilter ? (
          <NewInstanceButton klass={valueFilter} parent={resource.subject} />
        ) : (
          <>empty</>
        )
      ) : (
        <>
          {displayStyle.id === 'cards' && (
            <CardList members={members} subject={resource.subject} />
          )}
          {displayStyle.id === 'table' && (
            <Table
              resource={resource}
              members={members}
              columns={propsArrayFull}
            />
          )}
        </>
      )}
      {totalPages! > 1 && <Pagination />}
    </ContainerFull>
  );
}

type SortByPickerProps = {
  /** Subjects of the properties the collection can be sorted by. */
  properties: string[];
  selected: string | undefined;
  onSelect: (by: string | undefined) => void;
};

function SortByPicker({
  properties: subjects,
  selected,
  onSelect,
}: SortByPickerProps): JSX.Element {
  const resources = useResources(subjects);

  const options = React.useMemo<ComboBoxOption[]>(
    () =>
      subjects.map(subject => {
        const label = resources.get(subject)?.title ?? subject;

        return { value: subject, label, searchLabel: label };
      }),
    [subjects, resources],
  );

  return (
    <ComboBox
      options={options}
      selectedItem={selected}
      onSelect={onSelect}
      ariaLabel='sort by'
      placeholder='sort by...'
    />
  );
}

type CardListProps = {
  members: string[];
  subject: string;
};

function CardList({ members, subject }: CardListProps): JSX.Element {
  if (members.length === 0) {
    return <p>This collection is empty</p>;
  }

  return (
    <Masonry>
      {members.map((member, index) => (
        <GridItem key={subject + ' ' + member + index}>
          <ResourceCard
            initialInView={index < 10}
            key={member}
            subject={member}
          />
        </GridItem>
      ))}
    </Masonry>
  );
}

/** Use this to wrap around items to make them fit in the grid */
const DropDownMini = styled.div`
  display: inline-flex;
  margin-bottom: 1rem;
  flex: 1;
  max-width: 20rem;
`;

const GridItem = styled.div`
  margin: 0;
  /* display: grid; */
  /* grid-template-rows: 1fr auto; */
  word-break: break-word;
  overflow: hidden; /* fix for Firefox */
  break-inside: avoid-column;
  margin-bottom: ${p => p.theme.margin}rem;
`;

const ButtonsBar = styled.div`
  display: flex;
  flex-wrap: wrap;
  gap: ${p => p.theme.margin}rem;
`;

/**
 * A grid with columns and dynamic height items. Unfortunately, it does not work
 * properly with safari, where shadows appear cropped
 */
const Masonry = styled.div`
  column-count: 1;
  column-gap: ${props => props.theme.margin}rem;
  overflow: visible;
  box-sizing: border-box;

  @supports (grid-template-rows: masonry) {
    display: grid;
    grid-template-columns: repeat(1, 1fr);
    grid-template-rows: masonry;
    /* grid-gap: ${props => props.theme.margin}rem; */
    grid-column-gap: ${props => props.theme.margin}rem;
  }

  /* Masonry on small screens */
  @media only screen and (min-width: 600px) {
    grid-template-columns: repeat(2, 1fr);
    column-count: 2;
  }
  /* Masonry on medium-sized screens */
  @media only screen and (min-width: 1000px) {
    grid-template-columns: repeat(3, 1fr);
    column-count: 3;
  }
  /* Masonry on large screens */
  @media only screen and (min-width: 1400px) {
    grid-template-columns: repeat(4, 1fr);
    column-count: 4;
  }
`;

export default Collection;
