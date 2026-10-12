import { Resource, core, useStore } from '@tomic/react';
import { useRef, useState, type JSX } from 'react';
import { styled } from 'styled-components';
import { transition } from '../../../helpers/transition';
import { FaPlus } from 'react-icons/fa6';
import { SearchBox } from '../../../components/forms/SearchBox';
import { focusOffsetElement } from '../../../helpers/focusOffsetElement';
import { useOntologyContext } from '../OntologyContext';
import { newProperty } from '../ontologyUtils';

interface AddPropertyButtonProps {
  creator: Resource;
  type: 'required' | 'recommended';
}

export const BUTTON_WIDTH = 'calc(100% - 5.6rem + 4px)'; //Width is 100% - (2 * 1.8rem for button width) + (2rem for gaps) + (4px for borders)
/** Below this the property row wraps, so there is no icon column to leave room for. */
export const NARROW_BREAKPOINT = '40rem';

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
        ? core.properties.requires
        : core.properties.recommends;
    // A content-addressed property can already be listed.
    const listed = [
      ...((creator.get(core.properties.requires) ?? []) as string[]),
      ...((creator.get(core.properties.recommends) ?? []) as string[]),
    ];

    if (listed.includes(newValue)) {
      return;
    }

    creator.push(creatorProp, [newValue]);
    await creator.save();
  };

  const handleCreateProperty = async (shortname: string) => {
    const createdSubject = await newProperty(shortname, ontology, store);
    await handleSetValue(createdSubject);

    await addProperty(createdSubject);

    // After create a new property, we move focus to the description input of the new property.
    focusOffsetElement(-4, triggerRef.current!);
  };

  if (active) {
    return (
      <SearchBoxWrapper>
        <SearchBox
          autoFocus
          value=''
          onChange={handleSetValue}
          isA={core.classes.property}
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
  @media (max-width: ${NARROW_BREAKPOINT}) {
    width: 100%;
  }
`;

const AddButton = styled.button`
  background: none;
  border: 1px dashed ${p => p.theme.colors.bg2};
  height: 2.5rem;

  width: ${BUTTON_WIDTH};
  @media (max-width: ${NARROW_BREAKPOINT}) {
    width: 100%;
  }
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
