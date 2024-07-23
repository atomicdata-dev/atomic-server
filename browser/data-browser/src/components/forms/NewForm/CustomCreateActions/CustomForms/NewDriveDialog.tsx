import { core, useStore, server, dataBrowser } from '@tomic/react';
import { useState, useCallback, FormEvent, FC, useEffect, useId } from 'react';
import { styled } from 'styled-components';
import { stringToSlug } from '../../../../../helpers/stringToSlug';
import { Button } from '../../../../Button';
import {
  useDialog,
  Dialog,
  DialogContent,
  DialogActions,
} from '../../../../Dialog';
import Field from '../../../Field';
import { InputWrapper, InputStyled } from '../../../InputStyles';
import { CustomResourceDialogProps } from '../../useNewResourceUI';
import { useCreateAndNavigate } from '../../../../../hooks/useCreateAndNavigate';
import { useSettings } from '../../../../../helpers/AppSettings';

export const NewDriveDialog: FC<CustomResourceDialogProps> = ({
  parent,
  onClose,
}) => {
  const store = useStore();
  const nameFieldId = useId();
  const { setDrive } = useSettings();
  const [name, setName] = useState('');

  const createAndNavigate = useCreateAndNavigate();

  const onSuccess = useCallback(async () => {
    if (!name.trim()) return;

    const agent = store.getAgent();

    if (!agent || agent.subject === undefined) {
      throw new Error(
        'No agent set in the Store, required when creating a Drive',
      );
    }

    const newDrive = await createAndNavigate(
      server.classes.drive,
      {
        [core.properties.name]: name,
        [core.properties.write]: [agent.subject],
        [core.properties.read]: [agent.subject],
      },
      {
        noParent: true,
        onCreated: async resource => {
          // Add drive to the agents drive list.
          const agentResource = await store.getResource(agent.subject!);
          agentResource.push(server.properties.drives, [resource.subject]);
          await agentResource.save();

          // Create a default ontology.
          const ontologyName = stringToSlug(name);
          const ontology = await store.newResource({
            subject: await store.buildUniqueSubjectFromParts(
              ['defaultOntology'],
              resource.subject,
            ),
            isA: core.classes.ontology,
            parent: resource.subject,
            propVals: {
              [core.properties.shortname]: ontologyName,
              [core.properties.description]:
                `Default ontology for the ${name} drive`,
              [core.properties.classes]: [],
              [core.properties.properties]: [],
              [core.properties.instances]: [],
            },
          });

          await ontology.save();

          await resource.set(
            server.properties.defaultOntology,
            ontology.subject,
          );
          await resource.set(dataBrowser.properties.subResources, [
            ontology.subject,
          ]);
          await resource.save();
        },
      },
    );

    // Change current drive to new drive
    setDrive(newDrive.subject);

    onClose();
  }, [name, createAndNavigate, onClose, parent, setDrive, store]);

  const {
    dialogProps,
    show,
    close: hide,
  } = useDialog({ onSuccess, onCancel: onClose });

  useEffect(() => {
    show();
  }, []);

  return (
    <Dialog {...dialogProps}>
      <H1>New Drive</H1>
      <DialogContent>
        <form
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            hide(true);
          }}
        >
          <Field required label='Name' fieldId={nameFieldId}>
            <InputWrapper>
              <InputStyled
                id={nameFieldId}
                placeholder='My Drive'
                value={name}
                autoFocus={true}
                onChange={e => setName(e.target.value)}
              />
            </InputWrapper>
          </Field>
        </form>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => hide(false)} subtle>
          Cancel
        </Button>
        <Button onClick={() => hide(true)} disabled={!name.trim()}>
          Create
        </Button>
      </DialogActions>
    </Dialog>
  );
};

const H1 = styled.h1`
  margin: 0;
`;
