import { useState } from 'react';
import { Resource, core } from '@tomic/react';
import { styled } from 'styled-components';
import { FaPlus } from 'react-icons/fa';
import { NewFormDialog } from '../../components/forms/NewForm/NewFormDialog';
import { Dialog, useDialog } from '../../components/Dialog';
import { ClassSelectorDialog } from '../../components/ClassSelectorDialog';

interface CreateInstanceButtonProps {
  ontology: Resource;
}

export function CreateInstanceButton({ ontology }: CreateInstanceButtonProps) {
  const [classSelectorActive, setClassSelectorActive] = useState(false);
  const [classSubject, setClassSubject] = useState<string | undefined>();
  const [dialogProps, show, close, isOpen] = useDialog({
    onSuccess: () => {
      setClassSubject(undefined);
      ontology.save();
    },
  });

  const handleClassSelect = (subject: string | undefined) => {
    setClassSubject(subject);

    if (subject === undefined) {
      return;
    }

    show();
  };

  const handleSaveClick = (subject: string) => {
    ontology.push(core.properties.instances, [subject], true);
    close(true);
  };

  return (
    <>
      <InstanceButton onClick={() => setClassSelectorActive(true)}>
        <FaPlus />
        New Instance
      </InstanceButton>
      <ClassSelectorDialog
        show={classSelectorActive}
        bindShow={setClassSelectorActive}
        onClassSelect={handleClassSelect}
        ontologies={[ontology.subject]}
      />
      <Dialog {...dialogProps} width='50rem'>
        {isOpen && classSubject && (
          <NewFormDialog
            classSubject={classSubject}
            onCancel={() => close(false)}
            onSaveClick={handleSaveClick}
            parent={ontology.subject}
          />
        )}
      </Dialog>
    </>
  );
}

const InstanceButton = styled.button`
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 1ch;

  cursor: pointer;
  appearance: none;
  border: 2px dashed ${p => p.theme.colors.bg2};
  height: 10rem;
  background-color: transparent;
  border-radius: ${p => p.theme.radius};
  color: ${p => p.theme.colors.textLight};
  &:hover,
  &:focus {
    border-color: ${p => p.theme.colors.main};
    color: ${p => p.theme.colors.main};
    background-color: ${p => p.theme.colors.bg};
  }
`;
