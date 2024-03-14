import { Resource, useString, core } from '@tomic/react';
import { useState } from 'react';

import toast from 'react-hot-toast';
import { FaEdit, FaPlus } from 'react-icons/fa';
import { styled } from 'styled-components';
import { Button } from '../../components/Button';
import Markdown from '../../components/datatypes/Markdown';
import ResourceField from '../../components/forms/ResourceField';
import {
  IconButton,
  IconButtonVariant,
} from '../../components/IconButton/IconButton';
import { transition } from '../../helpers/transition';

interface ArticleDescriptionProps {
  resource: Resource;
  canEdit: boolean;
}

export function ArticleDescription({
  resource,
  canEdit,
}: ArticleDescriptionProps): JSX.Element {
  const [description] = useString(resource, core.properties.description);
  const [editMode, setEditMode] = useState(false);

  const saveContent = async () => {
    try {
      await resource.save();
      setEditMode(false);
      toast.success('Content saved');
    } catch (e) {
      setEditMode(true);
      toast.error('Could not save resource...');
    }
  };

  if (!editMode && canEdit && !description) {
    return (
      <AddContentButton onClick={() => setEditMode(true)}>
        <FaPlus />
        Add Content
      </AddContentButton>
    );
  }

  if (!editMode) {
    return (
      <DescriptionWrapper>
        {canEdit && (
          <EditButton
            onClick={() => setEditMode(true)}
            title='Edit content'
            variant={IconButtonVariant.Colored}
            color={'main'}
          >
            <FaEdit />
          </EditButton>
        )}
        <Markdown text={description ?? ''} />
      </DescriptionWrapper>
    );
  } else {
    return (
      <>
        <ResourceField
          resource={resource}
          propertyURL={core.properties.description}
        />
        <div>
          <Button onClick={saveContent}>Save</Button>
        </div>
      </>
    );
  }
}

const DescriptionWrapper = styled.div`
  position: relative;
`;

const EditButton = styled(IconButton)`
  position: absolute;
  top: 0;
  right: 0;
`;

const AddContentButton = styled.button`
  width: 100%;
  border: 1px solid ${({ theme }) => theme.colors.bg2};
  background-color: ${({ theme }) => theme.colors.bgBody};
  border-radius: ${({ theme }) => theme.radius};
  height: 25rem;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 1ch;
  color: ${({ theme }) => theme.colors.textLight};
  cursor: pointer;
  ${transition('border-color', 'color')};

  &:hover,
  &:focus {
    border-color: ${({ theme }) => theme.colors.main};
    color: ${({ theme }) => theme.colors.main};
  }
`;
