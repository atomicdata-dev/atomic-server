import {
  Datatype,
  classes,
  properties,
  useResource,
  validateDatatype,
} from '@tomic/react';
import React, { FormEvent, useCallback, useState } from 'react';
import { Button } from '../Button';
import { Dialog, DialogActions, DialogContent, useDialog } from '../Dialog';
import Field from '../forms/Field';
import { InputStyled, InputWrapper } from '../forms/InputStyles';
import { Base } from './Base';
import { useCreateAndNavigate } from './useCreateAndNavigate';
import { NewInstanceButtonProps } from './NewInstanceButtonProps';
import { stringToSlug } from '../../helpers/stringToSlug';
import { styled } from 'styled-components';

export function NewOntologyButton({
  klass,
  subtle,
  icon,
  IconComponent,
  parent,
  children,
  label,
}: NewInstanceButtonProps): JSX.Element {
  const ontology = useResource(klass);
  const [shortname, setShortname] = useState('');
  const [valid, setValid] = useState(false);

  const createResourceAndNavigate = useCreateAndNavigate(klass, parent);

  const onSuccess = useCallback(async () => {
    createResourceAndNavigate('ontology', {
      [properties.shortname]: shortname,
      [properties.isA]: [classes.ontology],
      [properties.description]: 'description',
      [properties.classes]: [],
      [properties.properties]: [],
      [properties.instances]: [],
    });
  }, [shortname, createResourceAndNavigate]);

  const [dialogProps, show, hide] = useDialog({ onSuccess });

  const onShortnameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = stringToSlug(e.target.value);
    setShortname(value);

    try {
      validateDatatype(value, Datatype.SLUG);
      setValid(true);
    } catch (_) {
      setValid(false);
    }
  };

  return (
    <>
      <Base
        onClick={show}
        title={ontology.title}
        icon={icon}
        IconComponent={IconComponent}
        subtle={subtle}
        label={label}
      >
        {children}
      </Base>
      <Dialog {...dialogProps}>
        <H1>New Ontology</H1>
        <DialogContent>
          <form
            onSubmit={(e: FormEvent) => {
              e.preventDefault();
              hide(true);
            }}
          >
            <Explanation>
              An ontology is a collection of classes and properties that
              together describe a concept. Great for data models.
            </Explanation>
            <Field required label='Shortname'>
              <InputWrapper>
                <InputStyled
                  placeholder='my-ontology'
                  value={shortname}
                  autoFocus={true}
                  onChange={onShortnameChange}
                />
              </InputWrapper>
            </Field>
          </form>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => hide(false)} subtle>
            Cancel
          </Button>
          <Button onClick={() => hide(true)} disabled={!valid}>
            Create
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}

const H1 = styled.h1`
  margin: 0;
`;

const Explanation = styled.p`
  color: ${p => p.theme.colors.textLight};
  max-width: 60ch;
`;
