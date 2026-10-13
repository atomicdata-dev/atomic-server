import { useProperty, Resource, Property, Datatype } from '@tomic/react';
import { styled } from 'styled-components';
import Field from './Field';
import Markdown from '../datatypes/Markdown';
import { InputWrapper, InputStyled } from './InputStyles';
import InputSwitcher from './InputSwitcher';
import { AtomicLink } from '../AtomicLink';
import { useId, type JSX } from 'react';
import { Row } from '../Row';
import { FaServer } from 'react-icons/fa6';

function generateErrorPropName(prop: Property): string {
  if (prop.error) {
    const endOfPath = prop.subject.split('/').pop();

    return endOfPath || 'error';
  } else return prop.shortname;
}

/** An input field for a single Property, rendered with a Label. Has a loading state. */
function ResourceField({
  handleDelete,
  propertyURL,
  resource,
  required,
  autoFocus,
  disabled,
  label: labelProp,
  commit,
  commitDebounceInterval,
}: IFieldProps): JSX.Element {
  const fieldId = useId();
  const labelId = useId();

  const property = useProperty(propertyURL);

  if (!property) {
    return (
      <CapitalizedField label={labelProp || 'loading...'} fieldId={fieldId}>
        <InputWrapper>
          <InputStyled
            disabled={disabled}
            placeholder='loading property...'
            id={fieldId}
          />
        </InputWrapper>
      </CapitalizedField>
    );
  }

  const label =
    labelProp ??
    (property.error ? generateErrorPropName(property) : property.shortname);

  if (property.isDynamic) {
    return (
      <CapitalizedField
        helper={
          <HelperText text={property.description} link={property.subject} />
        }
        label={label}
        disabled
        fieldId={fieldId}
      >
        <InputSwitcher
          id={fieldId}
          key={propertyURL + ' input-switcher'}
          data-testid={`input-${property.shortname}`}
          resource={resource}
          property={property}
          autoFocus={autoFocus}
          commit={commit}
          commitDebounceInterval={commitDebounceInterval}
          disabled
        />
        <Extra center gap='1ch'>
          <FaServer />
          <span>This field is calculated server-side.</span>
        </Extra>
      </CapitalizedField>
    );
  }

  return (
    <CapitalizedField
      helper={
        <HelperText text={property.description} link={property.subject} />
      }
      label={label}
      handleDelete={handleDelete}
      required={required}
      disabled={disabled}
      fieldId={fieldId}
      labelId={labelId}
      multiInput={property?.datatype === Datatype.RESOURCEARRAY}
    >
      <InputSwitcher
        id={fieldId}
        labelId={labelId}
        key={propertyURL + ' input-switcher'}
        data-test={`input-${property.shortname}`}
        resource={resource}
        property={property}
        required={required}
        autoFocus={autoFocus}
        disabled={disabled}
        commit={commit}
        commitDebounceInterval={commitDebounceInterval}
      />
    </CapitalizedField>
  );
}

interface HelperTextProps {
  text: string;
  link: string;
}

const HelperTextWrapper = styled.div`
  position: relative;
  margin-bottom: 0rem;
`;

const Extra = styled(Row)`
  color: ${props => props.theme.colors.textLight};
  margin-top: 0.5rem;
`;

function HelperText({ text, link }: HelperTextProps) {
  return (
    <HelperTextWrapper>
      <Markdown text={text} />
      <AtomicLink subject={link}>{link}</AtomicLink>
    </HelperTextWrapper>
  );
}

/** A single field in a Resource form should receive these */
export type InputProps = {
  id?: string;
  labelId?: string;
  /** The resource that is being edited */
  resource: Resource;
  /** The property of the resource that is being edited */
  property: Property;
  /** Whether the field must have a valid value before submitting */
  required?: boolean;
  disabled?: boolean;
  /** Whether the field should be focused on render */
  autoFocus?: boolean;
  /** Whether the field should commit on change */
  commit?: boolean;
  /** The debounce interval for the commit event in miliseconds */
  commitDebounceInterval?: number;
};

interface IFieldProps {
  /** Subject of the Property */
  propertyURL: string;
  /** The resource being edited */
  resource: Resource;
  /** Whether the field must have a valid value before submitting */
  required?: boolean;
  /** Overwrites the label with a custom one. Defaults to the shortname of the property */
  label?: string;
  disabled?: boolean;
  /** Whether the field should be focused on render */
  autoFocus?: boolean;
  /**
   * Whether the input should commit (save) on every change. Off by default:
   * the surrounding form saves the resource.
   */
  commit?: boolean;
  /** The debounce interval for the commit event in milliseconds */
  commitDebounceInterval?: number;
  /**
   * This function will be called when the delete icon is clicked. This should
   * remove the item from any parent list
   */
  handleDelete?: () => unknown;
}

export default ResourceField;

const CapitalizedField = styled(Field)`
  & label,
  & legend {
    text-transform: capitalize;
  }
`;
