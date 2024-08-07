import { useState } from 'react';
import { useHotkeys } from 'react-hotkeys-hook';
import { FaEdit } from 'react-icons/fa';
import { styled } from 'styled-components';
import {
  useProperty,
  useValue,
  Datatype,
  Resource,
  useCanWrite,
} from '@tomic/react';
import ValueComp from '../../ValueComp';
import { useSettings } from '../../../helpers/AppSettings';
import { ValueFormEdit } from './ValueFormEdit';

interface ValueFormProps {
  // Maybe pass Value instead of Resource?
  resource: Resource;
  propertyURL: string;
  /**
   * The datatype is automatically determined using the propertyUrl, but you can
   * also override it manually
   */
  datatype?: Datatype;
}

/**
 * A form for a single Value. Presents a normal value, but let's the user click
 * on a button to turn it into an input.
 */
export function ValueForm({ resource, propertyURL, datatype }: ValueFormProps) {
  const [editMode, setEditMode] = useState(false);
  const property = useProperty(propertyURL);
  const [value] = useValue(resource, propertyURL);
  const { agent } = useSettings();
  const [canWrite] = useCanWrite(resource);

  useHotkeys(
    'esc',
    () => {
      setEditMode(false);
    },
    {
      enableOnTags: ['INPUT', 'TEXTAREA', 'SELECT'],
    },
  );

  const hasAgent = agent !== undefined;

  const shouldShowEditButton = hasAgent && canWrite && !property.isDynamic;

  if (value === undefined) {
    return null;
  }

  if (!property && !datatype) {
    return <span title={`loading ${propertyURL}...`}>...</span>;
  }

  if (!editMode) {
    return (
      <ValueFormWrapper>
        <ValueComp value={value} datatype={datatype || property.datatype} />
        {shouldShowEditButton && (
          <EditButton title='Edit value'>
            <FaEdit onClick={() => setEditMode(!editMode)} />
          </EditButton>
        )}
      </ValueFormWrapper>
    );
  }

  return (
    <ValueFormEdit
      resource={resource}
      property={property}
      onClose={() => setEditMode(false)}
    />
  );
}

const ValueFormWrapper = styled.div`
  /* Used for positioning the edit button*/
  position: relative;
  flex: 1;
  word-wrap: break-word;
  max-width: 100%;
`;

const EditButton = styled.div`
  position: absolute;
  top: 0;
  color: ${p => p.theme.colors.main};
  right: 100%;
  cursor: pointer;
  opacity: 0;

  /** Only show hover edit button on mouse devices, prevents having to tap twice on some mobile devices */
  @media (hover: hover) and (pointer: fine) {
    ${ValueFormWrapper}:hover & {
      opacity: 0.5;
      &:hover {
        opacity: 1;
      }
    }
  }
`;
