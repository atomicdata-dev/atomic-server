import {
  core,
  forms,
  useArray,
  useProperty,
  useResource,
  useStore,
  type Resource,
} from '@tomic/react';
import { useState, type JSX } from 'react';
import { styled } from 'styled-components';
import toast from 'react-hot-toast';
import { FaTrash } from 'react-icons/fa6';
import Field from '@components/forms/Field';
import InputSwitcher from '@components/forms/InputSwitcher';
import { Button } from '@components/Button';
import { Column, Row } from '@components/Row';
import {
  ConfirmationDialog,
  ConfirmationDialogTheme,
} from '@components/ConfirmationDialog';
import { ConditionsEditor } from './ConditionsEditor';
import { deleteFormPage } from './deleteFormPage';

interface PageSettingsPanelProps {
  pageSubject: string;
  form: Resource;
}

/** Shown in the builder's right pane when a page is selected but no field is. */
export function PageSettingsPanel({
  pageSubject,
  form,
}: PageSettingsPanelProps): JSX.Element {
  const store = useStore();
  const page = useResource(pageSubject);
  const nameProp = useProperty(core.properties.name);
  const [pages] = useArray(form, forms.properties.formPages);
  const [showDelete, setShowDelete] = useState(false);

  // The last page can't go — a form without pages has nowhere to put fields.
  const canDelete = pages.length > 1;

  const onConfirmDelete = async () => {
    try {
      await deleteFormPage(store, form, pages, pageSubject);
    } catch (error) {
      toast.error((error as Error).message);
    }
  };

  return (
    <Panel>
      <Field label='Name' required>
        <InputSwitcher
          commit
          resource={page}
          property={nameProp}
          required
          data-testid='page-name-input'
        />
      </Field>
      <ConditionsEditor resource={page} form={form} beforePage={pageSubject} />
      <Spacer />
      {canDelete && (
        <>
          <Divider />
          <DeleteButton
            type='button'
            subtle
            onClick={() => setShowDelete(true)}
            data-testid='delete-page'
          >
            <Row gap='.5rem' center>
              <FaTrash /> Delete page
            </Row>
          </DeleteButton>
          <ConfirmationDialog
            title='Delete page'
            confirmLabel='Delete'
            show={showDelete}
            bindShow={setShowDelete}
            theme={ConfirmationDialogTheme.Alert}
            onConfirm={onConfirmDelete}
          >
            <p>
              Are you sure you want to delete this page? Its fields will no
              longer be part of the form.
            </p>
          </ConfirmationDialog>
        </>
      )}
    </Panel>
  );
}

const Panel = styled(Column)`
  gap: 0.75rem;
  min-height: 100%;
`;

const Spacer = styled.div`
  flex: 1;
`;

const DeleteButton = styled(Button)`
  align-self: flex-end !important;
  color: ${p => p.theme.colors.alert};
`;

const Divider = styled.hr`
  border-top: 1px solid ${p => p.theme.colors.bg2};
  width: 100%;
`;
