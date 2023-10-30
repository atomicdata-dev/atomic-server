import { Resource, Store, urls, useStore } from '@tomic/react';
import React, { useRef, useState } from 'react';
import { styled } from 'styled-components';
import { transition } from '../../../helpers/transition';
import { FaPlus } from 'react-icons/fa';
import { SearchBox } from '../../../components/forms/SearchBox';
import { focusOffsetElement } from '../../../helpers/focusOffsetElement';
import { useOntologyContext } from '../OntologyContext';

interface AddPropertyButtonProps {
  creator: Resource;
  type: 'required' | 'recommended';
}

const BUTTON_WIDTH = 'calc(100% - 5.6rem + 4px)'; //Width is 100% - (2 * 1.8rem for button width) + (2rem for gaps) + (4px for borders)

async function newProperty(shortname: string, parent: Resource, store: Store) {
  const subject = `${parent.getSubject()}/property/${shortname}`;
  const resource = store.getResourceLoading(subject, { newResource: true });

  await resource.addClasses(store, urls.classes.property);
  await resource.set(urls.properties.shortname, shortname, store);
  await resource.set(urls.properties.description, 'a property', store);
  await resource.set(urls.properties.datatype, urls.datatypes.string, store);
  await resource.set(urls.properties.parent, parent.getSubject(), store);
  await resource.save(store);

  return subject;
}

export function AddPropertyButton({
  creator,
  type,
}: AddPropertyButtonProps): JSX.Element {
  const store = useStore();
  const triggerRef = useRef<HTMLButtonElement>(null);

  const [active, setActive] = useState(false);

  const { ontology, addProperty } = useOntologyContext();

  const handleSetValue = async (newValue: string | undefined) => {
    setActive(false);

    if (!newValue) {
      return;
    }

    const creatorProp =
      type === 'required'
        ? urls.properties.requires
        : urls.properties.recommends;
    creator.pushPropVal(creatorProp, [newValue]);
    await creator.save(store);
  };

  const handleCreateProperty = async (shortname: string) => {
    const createdSubject = await newProperty(shortname, ontology, store);
    await handleSetValue(createdSubject);

    await addProperty(createdSubject);

    focusOffsetElement(-4, triggerRef.current!);
  };

  if (active) {
    return (
      <SearchBoxWrapper>
        <SearchBox
          autoFocus
          value=''
          onChange={handleSetValue}
          isA={urls.classes.property}
          onClose={() => setActive(false)}
          onCreateItem={handleCreateProperty}
        />
      </SearchBoxWrapper>
    );
  }

  return (
    <AddButton
      title={`add ${type} property`}
      onClick={() => setActive(true)}
      ref={triggerRef}
    >
      <FaPlus />
    </AddButton>
  );
}

const SearchBoxWrapper = styled.div`
  width: ${BUTTON_WIDTH};
`;

const AddButton = styled.button`
  background: none;
  border: 1px dashed ${p => p.theme.colors.bg2};
  height: 2.5rem;

  width: ${BUTTON_WIDTH};
  border-radius: ${p => p.theme.radius};
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 1ch;
  cursor: pointer;
  color: ${p => p.theme.colors.textLight};

  ${transition('border-color', 'color')}
  &:hover,
  &:focus-visible {
    border-style: solid;
    border-color: ${p => p.theme.colors.main};
    color: ${p => p.theme.colors.main};
  }
`;
