import React, { useState, type JSX } from 'react';
import { FaAsterisk, FaInfo, FaTrash } from 'react-icons/fa6';
import { styled } from 'styled-components';
import { Collapse } from '../Collapse';
import { IconButton, IconButtonVariant } from '../IconButton/IconButton';
import { Flex, Row } from '../Row';
import { ErrMessage } from './InputStyles';
import { complement } from 'polished';

interface FieldProps {
  /** Label */
  label?: string;
  /** Rendered before the label text in the label row (e.g. a checkbox). */
  labelPrefix?: React.ReactNode;
  /** Rendered at the end of the label row (e.g. a button acting on the whole
   * field, rather than on one of its inputs). */
  labelAction?: React.ReactNode;
  /** Helper text / collapsible info */
  helper?: React.ReactNode;
  /** If true the helper text will always be visible and no button to toggle it will be shown */
  helperAlwaysVisible?: boolean;
  /** Here goes the input */
  children: React.ReactNode;
  /** If the field is required. Shows an asterisk with hover text */
  required?: boolean;
  disabled?: boolean;
  /** The error to be shown in the component */
  error?: Error;

  /** The id of the field. This is used to link the label with the input */
  fieldId?: string;
  labelId?: string;
  /**
   * If the field contains multiple inputs like an array.
   * This will make the component render a fieldset + legend instead of a label.
   */
  multiInput?: boolean;
  className?: string;
  /**
   * This function will be called when the delete icon is clicked. This should
   * remove the item from any parent list
   */
  handleDelete?: (url: string) => unknown;
}

/** High level form field skeleton. Pass the actual input as a child component. */
function Field({
  label,
  labelPrefix,
  labelAction,
  helper,
  helperAlwaysVisible,
  children,
  error,
  handleDelete,
  required,
  disabled,
  fieldId,
  labelId,
  multiInput,
  className,
}: FieldProps): JSX.Element {
  const [collapsedHelper, setCollapsed] = useState(true);

  return (
    <FieldStyled as={multiInput ? 'fieldset' : undefined} className={className}>
      <LabelWrapper>
        <Row gap='0.4rem' center>
          {labelPrefix}
          <FieldLabel
            data-test={`field-label-${label}`}
            htmlFor={fieldId}
            id={labelId}
            as={multiInput ? 'legend' : undefined}
          >
            {label}
            {required && <Astrisk title='Required field' size='0.6em' />}
          </FieldLabel>
          {!!helper && !helperAlwaysVisible && (
            <IconButton
              variant={IconButtonVariant.Outline}
              color='textLight'
              type='button'
              size='0.7rem'
              onClick={() => setCollapsed(!collapsedHelper)}
              title='Show helper'
            >
              <FaInfo />
            </IconButton>
          )}
          {!disabled && handleDelete && (
            <IconButton
              variant={IconButtonVariant.Outline}
              title='Delete this property'
              color='textLight'
              type='button'
              size='0.7rem'
              onClick={() => handleDelete('test')}
            >
              <FaTrash />
            </IconButton>
          )}
          {labelAction}
        </Row>
        {!!helper && (
          <FieldHelper>
            <Collapse open={!collapsedHelper || helperAlwaysVisible}>
              {helper}
              {required && !helperAlwaysVisible && <div>Required field.</div>}
            </Collapse>
          </FieldHelper>
        )}
      </LabelWrapper>
      {children}
      {error && (
        <ErrMessage title={`Error: ${JSON.stringify(error)}`}>
          {error.message}
        </ErrMessage>
      )}
    </FieldStyled>
  );
}

const FieldStyled = styled.div`
  padding: 0;
  border: none;
  background-color: none;

  // Removes default 1px margin on fieldset.
  &:is(fieldset) {
    margin-inline: 0;
  }

  ${Flex} > & {
    margin-bottom: 0;
  }
`;

export const FieldLabel = styled.label`
  text-transform: capitalize;
  display: inline-flex;
  gap: 0.2rem;
  align-items: center;
  font-weight: bold;
`;

Field.Label = FieldLabel;

const Astrisk = styled(FaAsterisk)`
  margin-bottom: 0.5em;
  color: ${p => complement(p.theme.colors.main)};
`;

export const FieldHelper = styled.div`
  font-size: 0.9em;
  color: ${props => props.theme.colors.textLight};
`;

Field.Helper = FieldHelper;

const LabelWrapper = styled.div`
  margin-bottom: ${p => p.theme.size(2)};
`;

export default Field;
