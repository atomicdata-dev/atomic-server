import {
  Datatype,
  core,
  setClassConstraint,
  useCanWrite,
  useEffectiveConstraint,
  useResource,
  useStore,
  type Constraint,
  type ConstraintPatch,
  type Resource,
} from '@tomic/react';
import { useCallback, useState, type JSX } from 'react';
import toast from 'react-hot-toast';
import { Column, Row } from '../../../components/Row';
import { styled } from 'styled-components';
import { FaCaretRight } from 'react-icons/fa6';
import { Button } from '../../../components/Button';
import { IconButton } from '../../../components/IconButton/IconButton';
import { ResourceInline } from '../../ResourceInline';
import { BUTTON_WIDTH, NARROW_BREAKPOINT } from './AddPropertyButton';
import { FaPlus, FaXmark } from 'react-icons/fa6';
import { ErrorChip } from '../../../components/forms/ErrorChip';
import {
  InputStyled,
  InputWrapper,
} from '../../../components/forms/InputStyles';
import { SearchBox } from '../../../components/forms/SearchBox';
import { LabelText } from '../LabelText';
import { newClass } from '../ontologyUtils';
import { useOntologyContext } from '../OntologyContext';
import { TagOptionsEditor } from '../Property/EnumFormPart';
import { useClassEnumHandlers } from '../Property/useEnumHandlers';
import { optionSubjects } from '../../../helpers/withConstraint';

const NUMBER_TYPES: string[] = [Datatype.INTEGER, Datatype.FLOAT];
const TEXT_TYPES: string[] = [
  Datatype.STRING,
  Datatype.MARKDOWN,
  Datatype.SLUG,
  Datatype.URI,
];
const LINK_TYPES: string[] = [Datatype.ATOMIC_URL, Datatype.RESOURCEARRAY];

interface ClassConstraintEditorProps {
  classResource: Resource;
  propertySubject: string;
}

/**
 * The constraints one class puts on one of its properties: a linked class,
 * options, limits, a pattern. They are stored in the class's `constraints`
 * map, so the property itself stays untouched (properties are immutable) and
 * every class can say something different about the same property.
 */
export function ClassConstraintEditor({
  classResource,
  propertySubject,
}: ClassConstraintEditorProps): JSX.Element | null {
  const property = useResource(propertySubject);
  const [open, setOpen] = useState(false);
  const datatype = (property.get(core.properties.datatype) as string) ?? '';

  if (
    property.loading ||
    !(
      NUMBER_TYPES.includes(datatype) ||
      TEXT_TYPES.includes(datatype) ||
      LINK_TYPES.includes(datatype)
    )
  ) {
    return null;
  }

  return (
    <Wrapper>
      <Toggle
        type='button'
        aria-expanded={open}
        onClick={() => setOpen(o => !o)}
      >
        <Caret $open={open} />
        <span>Constraints</span>
        {!open && (
          <ConstraintSummary
            classResource={classResource}
            propertySubject={propertySubject}
          />
        )}
      </Toggle>
      {/* Only mounted while open: every property line has one of these. */}
      {open && (
        <ConstraintFields
          classResource={classResource}
          propertySubject={propertySubject}
          datatype={datatype}
          title={property.title}
        />
      )}
    </Wrapper>
  );
}

const Wrapper = styled.div`
  margin-top: 0.15rem;
`;

const Toggle = styled.button`
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
  max-width: 100%;
  padding: 0.1rem 0.25rem 0.1rem 0;
  border: none;
  background: transparent;
  font: inherit;
  font-size: 0.85em;
  color: ${p => p.theme.colors.textLight};
  cursor: pointer;

  &:hover,
  &:focus-visible {
    color: ${p => p.theme.colors.main};
  }
`;

const Caret = styled(FaCaretRight)<{ $open: boolean }>`
  flex-shrink: 0;
  transition: transform ${p => p.theme.animation.duration} ease-in-out;
  transform: rotate(${p => (p.$open ? '90deg' : '0deg')});
`;

const Summary = styled.span`
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  opacity: 0.8;
  &::before {
    content: '· ';
  }
`;

/** What is set, in a few words, so a collapsed section still says something. */
function ConstraintSummary({
  classResource,
  propertySubject,
}: ClassConstraintEditorProps): JSX.Element | null {
  const c = useEffectiveConstraint([classResource.subject], propertySubject);
  const parts: JSX.Element[] = [];

  if (c.minimum !== undefined) parts.push(<>min {c.minimum}</>);

  if (c.maximum !== undefined) parts.push(<>max {c.maximum}</>);

  if (c.minLength !== undefined) parts.push(<>min {c.minLength} chars</>);

  if (c.maxLength !== undefined) parts.push(<>max {c.maxLength} chars</>);

  if (c.minItems !== undefined) parts.push(<>min {c.minItems} items</>);

  if (c.maxItems !== undefined) parts.push(<>max {c.maxItems} items</>);

  if (c.pattern) parts.push(<>pattern</>);

  if (c.class) parts.push(<>linked class</>);

  if (optionSubjects(c).length > 0) parts.push(<>options</>);

  if (parts.length === 0) return null;

  return (
    <Summary>
      {parts.map((part, i) => (
        <span key={i}>
          {i > 0 && ', '}
          {part}
        </span>
      ))}
    </Summary>
  );
}

/** Inputs on one grid: pairs share the row 50/50, wide fields span both. */
const Grid = styled.div`
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.5rem 0.75rem;
  padding: 0.4rem 0 0.25rem;
  /* Same right edge as the add-property row below. */
  width: ${BUTTON_WIDTH};
  @media (max-width: ${NARROW_BREAKPOINT}) {
    width: 100%;
  }

  & > .span-all {
    grid-column: 1 / -1;
  }
`;

const FieldError = styled(ErrorChip).attrs({ noMovement: true })`
  top: 0;
  margin-top: 0.4rem;
  display: block;
`;

const FieldLabel = styled.label`
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
  min-width: 0;
  font-size: 0.85em;
  font-weight: normal;
  color: ${p => p.theme.colors.textLight};
`;

function ConstraintFields({
  classResource,
  propertySubject,
  datatype,
  title,
}: ClassConstraintEditorProps & {
  datatype: string;
  title: string;
}): JSX.Element {
  const canWrite = useCanWrite(classResource);
  const constraint = useEffectiveConstraint(
    [classResource.subject],
    propertySubject,
  );

  const isNumber = NUMBER_TYPES.includes(datatype);
  const isText = TEXT_TYPES.includes(datatype);
  const isLink = LINK_TYPES.includes(datatype);
  const isArray = datatype === Datatype.RESOURCEARRAY;

  return (
    <Grid data-testid={`constraints-${title}`}>
      {isLink && (
        <LinkConstraints
          classResource={classResource}
          propertySubject={propertySubject}
          constraint={constraint}
          disabled={!canWrite}
        />
      )}
      {isNumber && (
        <>
          <NumberField
            label='Minimum'
            keyword='minimum'
            classResource={classResource}
            propertySubject={propertySubject}
            value={constraint.minimum}
            disabled={!canWrite}
          />
          <NumberField
            label='Maximum'
            keyword='maximum'
            classResource={classResource}
            propertySubject={propertySubject}
            value={constraint.maximum}
            disabled={!canWrite}
          />
        </>
      )}
      {isText && (
        <>
          <NumberField
            label='Min length'
            keyword='minLength'
            count
            classResource={classResource}
            propertySubject={propertySubject}
            value={constraint.minLength}
            disabled={!canWrite}
          />
          <NumberField
            label='Max length'
            keyword='maxLength'
            count
            classResource={classResource}
            propertySubject={propertySubject}
            value={constraint.maxLength}
            disabled={!canWrite}
          />
          <PatternField
            classResource={classResource}
            propertySubject={propertySubject}
            value={constraint.pattern?.source}
            disabled={!canWrite}
          />
        </>
      )}
      {isArray && (
        <>
          <NumberField
            label='Min items'
            keyword='minItems'
            count
            classResource={classResource}
            propertySubject={propertySubject}
            value={constraint.minItems}
            disabled={!canWrite}
          />
          <NumberField
            label='Max items'
            keyword='maxItems'
            count
            classResource={classResource}
            propertySubject={propertySubject}
            value={constraint.maxItems}
            disabled={!canWrite}
          />
        </>
      )}
    </Grid>
  );
}

/** Writes a patch to the class entry and saves the class. Errors become toasts. */
function useConstraintWriter(classResource: Resource, propertySubject: string) {
  return useCallback(
    async (patch: ConstraintPatch): Promise<string | undefined> => {
      try {
        await setClassConstraint(classResource, propertySubject, patch);
        await classResource.save();

        return undefined;
      } catch (e) {
        const message = (e as Error).message;
        toast.error(message);

        return message;
      }
    },
    [classResource, propertySubject],
  );
}

interface FieldProps {
  classResource: Resource;
  propertySubject: string;
  disabled: boolean;
}

function NumberField({
  label,
  keyword,
  count,
  value,
  classResource,
  propertySubject,
  disabled,
}: FieldProps & {
  label: string;
  keyword:
    | 'minimum'
    | 'maximum'
    | 'minLength'
    | 'maxLength'
    | 'minItems'
    | 'maxItems';
  /** A whole number of zero or more. */
  count?: boolean;
  value: number | undefined;
}): JSX.Element {
  const write = useConstraintWriter(classResource, propertySubject);
  const [draft, setDraft] = useState<string | undefined>();
  const [error, setError] = useState<string>();

  const commit = async () => {
    if (draft === undefined) return;

    const parsed = draft.trim() === '' ? undefined : Number(draft);

    if (parsed !== undefined && !Number.isFinite(parsed)) {
      setError('Enter a number');

      return;
    }

    if (
      parsed !== undefined &&
      count &&
      (!Number.isInteger(parsed) || parsed < 0)
    ) {
      setError('Enter a whole number, zero or more');

      return;
    }

    setError(await write({ [keyword]: parsed }));
    setDraft(undefined);
  };

  return (
    <FieldLabel>
      <span>{label}</span>
      <InputWrapper $invalid={!!error}>
        <InputStyled
          type='number'
          aria-label={label}
          disabled={disabled}
          value={draft ?? value ?? ''}
          onChange={e => setDraft(e.target.value)}
          onBlur={commit}
        />
      </InputWrapper>
      {error && <FieldError>{error}</FieldError>}
    </FieldLabel>
  );
}

function PatternField({
  value,
  classResource,
  propertySubject,
  disabled,
}: FieldProps & { value: string | undefined }): JSX.Element {
  const write = useConstraintWriter(classResource, propertySubject);
  const [draft, setDraft] = useState<string | undefined>();
  const [error, setError] = useState<string>();

  const commit = async () => {
    if (draft === undefined) return;

    setError(await write({ pattern: draft.trim() === '' ? undefined : draft }));
    setDraft(undefined);
  };

  return (
    <FieldLabel className='span-all'>
      <span>Pattern (regular expression)</span>
      <InputWrapper $invalid={!!error}>
        <InputStyled
          aria-label='Pattern'
          disabled={disabled}
          value={draft ?? value ?? ''}
          onChange={e => setDraft(e.target.value)}
          onBlur={commit}
        />
      </InputWrapper>
      {error && <FieldError>{error}</FieldError>}
    </FieldLabel>
  );
}

function LinkConstraints({
  classResource,
  propertySubject,
  constraint,
  disabled,
}: FieldProps & { constraint: Constraint }): JSX.Element {
  const { ontology } = useOntologyContext();
  const write = useConstraintWriter(classResource, propertySubject);
  const options = optionSubjects(constraint);
  const { addTag, removeTag } = useClassEnumHandlers(
    classResource,
    propertySubject,
    ontology,
  );

  return (
    <LinkWrapper className='span-all'>
      <LinkedClassField
        classResource={classResource}
        propertySubject={propertySubject}
        value={constraint.class}
        disabled={disabled}
        label='Linked class'
      />
      {constraint.class ? (
        <InstanceOptions
          linkedClass={constraint.class}
          options={options}
          disabled={disabled}
          onChange={next => write({ enum: next.length > 0 ? next : undefined })}
        />
      ) : (
        <TagOptionsEditor
          tags={options}
          parent={ontology.subject}
          onAdd={addTag}
          onRemove={removeTag}
          disabled={disabled}
        />
      )}
    </LinkWrapper>
  );
}

const LinkWrapper = styled(Column)`
  min-width: 0;
`;

/**
 * Picks the class a link points at, as the `class` constraint of one class for
 * one property. Shared by the constraints section under a property line and
 * the property's own dialog.
 */
export function LinkedClassField({
  classResource,
  propertySubject,
  value,
  disabled,
  label,
}: FieldProps & { value: string | undefined; label: string }): JSX.Element {
  const store = useStore();
  const { ontology } = useOntologyContext();
  const write = useConstraintWriter(classResource, propertySubject);

  const createClass = useCallback(
    async (shortname: string) => {
      const created = await newClass(shortname, ontology, store);
      await write({ class: created });
    },
    [ontology, store, write],
  );

  return (
    <Column as='label' gap='0.25rem'>
      <LabelText>{label}</LabelText>
      <SearchBox
        // Creating a class does not close the picker, so start a fresh one.
        key={value ?? 'none'}
        disabled={disabled}
        value={value}
        onChange={next => write({ class: next })}
        isA={core.classes.class}
        onCreateItem={createClass}
      />
    </Column>
  );
}

interface InstanceOptionsProps {
  linkedClass: string;
  options: string[];
  disabled: boolean;
  onChange: (next: string[]) => void;
}

/** Restricts a link to a fixed set of resources of the linked class. */
function InstanceOptions({
  linkedClass,
  options,
  disabled,
  onChange,
}: InstanceOptionsProps): JSX.Element {
  const [adding, setAdding] = useState(false);

  return (
    <Column gap='0.5rem'>
      <LabelText>Allows only</LabelText>
      {options.map(option => (
        <Row key={option} center>
          <ResourceInline subject={option} />
          {!disabled && (
            <IconButton
              title='Remove from the allowed list'
              onClick={() => onChange(options.filter(o => o !== option))}
            >
              <FaXmark />
            </IconButton>
          )}
        </Row>
      ))}
      {!disabled && !adding && (
        <Button
          subtle
          aria-label='Add an item to the allows-only list'
          onClick={() => setAdding(true)}
        >
          <FaPlus /> Add
        </Button>
      )}
      {!disabled && adding && (
        <SearchBox
          autoFocus
          hideClearButton
          value={undefined}
          isA={linkedClass}
          onClose={() => setAdding(false)}
          onChange={value => {
            setAdding(false);

            if (value && !options.includes(value)) {
              onChange([...options, value]);
            }
          }}
        />
      )}
    </Column>
  );
}
