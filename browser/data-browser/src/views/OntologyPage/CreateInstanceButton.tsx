import { useState } from 'react';
import { Resource, core } from '@tomic/react';
import { styled } from 'styled-components';
import { FaPlus } from 'react-icons/fa';
import { ResourceSelector } from '../../components/forms/ResourceSelector';
import { Column } from '../../components/Row';
import { NewFormDialog } from '../../components/forms/NewForm/NewFormDialog';
import { Dialog, useDialog } from '../../components/Dialog';

interface CreateInstanceButtonProps {
  ontology: Resource;
}

export function CreateInstanceButton({ ontology }: CreateInstanceButtonProps) {
  const [active, setActive] = useState(false);
  const [classSubject, setClassSubject] = useState<string | undefined>();
  const [dialogProps, show, close, isOpen] = useDialog({
    onSuccess: () => {
      setClassSubject(undefined);
      setActive(false);
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
      {!active ? (
        <InstanceButton onClick={() => setActive(true)}>
          <FaPlus />
          New Instance
        </InstanceButton>
      ) : (
        <>
          <ChooseClassFormWrapper>
            <Column>
              <strong>Select the class for this instance</strong>
              <ResourceSelector
                autoFocus
                isA={core.classes.class}
                setSubject={handleClassSelect}
                value={classSubject}
              />
            </Column>
          </ChooseClassFormWrapper>
          <Dialog {...dialogProps}>
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
      )}
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

const ChooseClassFormWrapper = styled.div`
  min-height: 10rem;
  border: 2px dashed ${p => p.theme.colors.bg2};
  background-color: ${p => p.theme.colors.bg};
  border-radius: ${p => p.theme.radius};
  padding: ${p => p.theme.margin}rem;
`;
