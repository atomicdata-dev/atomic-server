import { useState } from 'react';
import { Resource, core } from '@tomic/react';
import { styled } from 'styled-components';
import { FaPlus } from 'react-icons/fa6';
import { NewFormDialog } from '../../components/forms/NewForm/NewFormDialog';
import { Dialog, useDialog } from '../../components/Dialog';
import { ClassSelectorDialog } from '../../components/ClassSelectorDialog';

interface CreateInstanceButtonProps {
  ontology: Resource;
}

export function CreateInstanceButton({ ontology }: CreateInstanceButtonProps) {
  const [classSelectorActive, setClassSelectorActive] = useState(false);
  const [classSubject, setClassSubject] = useState<string | undefined>();
  const [createdInstanceSubject, setCreatedInstanceSubject] =
    useState<string>();

  const [dialogProps, show, close] = useDialog({
    onSuccess: async () => {
      ontology.push(core.properties.instances, [createdInstanceSubject], true);
      await ontology.save();

      // Wait for the new instance card to render, then scroll it into view.
      // The card uses IntersectionObserver to defer expensive content; if it
      // never enters the viewport its title stays as a raw DID placeholder.
      let attempts = 0;

      const tryScroll = () => {
        const el = document.querySelector(
          `[about="${createdInstanceSubject}"]`,
        );

        if (el) {
          el.scrollIntoView({ behavior: 'instant', block: 'center' });
          setCreatedInstanceSubject(undefined);
          setClassSubject(undefined);

          return;
        }

        if (attempts++ < 30) {
          requestAnimationFrame(tryScroll);
        }
      };

      requestAnimationFrame(tryScroll);
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
    setCreatedInstanceSubject(subject);
    setClassSubject(undefined);
    close(true);
  };

  const handleCancel = () => {
    setClassSubject(undefined);
    close(false);
  };

  return (
    <>
      <InstanceButton onClick={() => setClassSelectorActive(true)}>
        <FaPlus />
        <span>New Instance</span>
      </InstanceButton>
      <ClassSelectorDialog
        show={classSelectorActive}
        bindShow={setClassSelectorActive}
        onClassSelect={handleClassSelect}
        ontologies={[ontology.subject]}
      />
      <Dialog {...dialogProps} width='50rem'>
        {dialogProps.show && classSubject && (
          <NewFormDialog
            classSubject={classSubject}
            onCancel={handleCancel}
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
