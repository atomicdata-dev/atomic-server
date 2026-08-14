import {
  forms,
  useArray,
  useResource,
  useStore,
  useString,
  useSubject,
  useValue,
  type JSONValue,
  type Resource,
} from '@tomic/react';
import type { JSX } from 'react';
import { styled } from 'styled-components';
import { FaPlus, FaTrash } from 'react-icons/fa6';
import Field from '@components/forms/Field';
import { BasicSelect } from '@components/forms/BasicSelect';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { Button } from '@components/Button';
import { Column, Row } from '@components/Row';
import {
  IconButton,
  IconButtonVariant,
} from '@components/IconButton/IconButton';
import {
  previousQuestions,
  useFormQuestions,
  type FormQuestionRef,
} from './useFormQuestions';

const OPERATORS: Array<{ value: string; label: string }> = [
  { value: 'equals', label: 'equals' },
  { value: 'not-equals', label: 'does not equal' },
  { value: 'contains', label: 'contains' },
  { value: 'greater-than', label: 'greater than' },
  { value: 'less-than', label: 'less than' },
];

interface ConditionsEditorProps {
  /** The page, field, or layout block that owns the conditions. */
  resource: Resource;
  form: Resource;
  /** When editing a field, only earlier questions are offered. */
  beforeField?: string;
  /** When editing a page, only questions on earlier pages are offered. */
  beforePage?: string;
}

export function ConditionsEditor({
  resource,
  form,
  beforeField,
  beforePage,
}: ConditionsEditorProps): JSX.Element {
  const store = useStore();
  const [pages] = useArray(form, forms.properties.formPages);
  const questions = useFormQuestions(form);
  const available = previousQuestions(questions, pages, {
    beforeField,
    beforePage,
  });
  const [conditionSubjects, setConditionSubjects] = useArray(
    resource,
    forms.properties.formConditions,
    { commit: true },
  );

  const addCondition = async () => {
    const first = available[0];

    if (!first) return;

    const cond = await store.newResource({
      parent: resource.subject,
      isA: forms.classes.formCondition,
      propVals: {
        [forms.properties.formConditionField]: first.subject,
        [forms.properties.formConditionOperator]: 'equals',
        [forms.properties.formConditionValue]: defaultValueFor(first),
      },
    });
    await cond.save();
    setConditionSubjects([...conditionSubjects, cond.subject]);
  };

  const removeCondition = async (subject: string) => {
    setConditionSubjects(conditionSubjects.filter(s => s !== subject));
    const cond = await store.getResource(subject);
    await cond.destroy();
  };

  return (
    <Field
      label='Show when'
      helper='All of these must match. Leave empty to always show.'
    >
      <Column gap='0.4rem'>
        {conditionSubjects.map((subject, index) => (
          <div key={subject}>
            {index > 0 && <AndLabel>and</AndLabel>}
            <ConditionRow
              subject={subject}
              available={available}
              onRemove={() => removeCondition(subject)}
            />
          </div>
        ))}
        <AddButton
          type='button'
          subtle
          data-testid='add-condition'
          disabled={available.length === 0}
          title={
            available.length === 0
              ? 'Add a question before this one first'
              : undefined
          }
          onClick={addCondition}
        >
          <Row gap='.5rem' center>
            <FaPlus /> Add condition
          </Row>
        </AddButton>
      </Column>
    </Field>
  );
}

interface ConditionRowProps {
  subject: string;
  available: FormQuestionRef[];
  onRemove: () => void;
}

function ConditionRow({
  subject,
  available,
  onRemove,
}: ConditionRowProps): JSX.Element {
  const resource = useResource(subject);
  const [fieldSubject, setFieldSubject] = useSubject(
    resource,
    forms.properties.formConditionField,
    { commit: true },
  );
  const [operator, setOperator] = useString(
    resource,
    forms.properties.formConditionOperator,
    { commit: true },
  );
  const [value, setValue] = useValue(
    resource,
    forms.properties.formConditionValue,
    { commit: true, validate: false },
  );

  const selected =
    available.find(q => q.subject === fieldSubject) ?? available[0];

  const onFieldChange = (nextSubject: string) => {
    const next = available.find(q => q.subject === nextSubject);

    if (!next) return;

    setFieldSubject(next.subject);
    setValue(defaultValueFor(next));
  };

  return (
    <Row gap='0.4rem' center>
      <BasicSelect
        data-testid='condition-field'
        value={fieldSubject ?? ''}
        onChange={e => onFieldChange(e.target.value)}
      >
        {available.map(q => (
          <option key={q.subject} value={q.subject}>
            {q.label}
          </option>
        ))}
      </BasicSelect>
      <BasicSelect
        data-testid='condition-operator'
        value={operator ?? 'equals'}
        onChange={e => setOperator(e.target.value)}
      >
        {OPERATORS.map(op => (
          <option key={op.value} value={op.value}>
            {op.label}
          </option>
        ))}
      </BasicSelect>
      <ValueInput
        question={selected}
        value={parseConditionValue(value)}
        onChange={setValue}
      />
      <IconButton
        variant={IconButtonVariant.Simple}
        size='0.8rem'
        color='textLight'
        title='Remove condition'
        type='button'
        data-testid='remove-condition'
        onClick={onRemove}
      >
        <FaTrash />
      </IconButton>
    </Row>
  );
}

function ValueInput({
  question,
  value,
  onChange,
}: {
  question: FormQuestionRef | undefined;
  value: JSONValue;
  onChange: (value: JSONValue) => void;
}): JSX.Element {
  if (!question) {
    return (
      <InputWrapper>
        <InputStyled data-testid='condition-value' disabled />
      </InputWrapper>
    );
  }

  if (question.type === 'checkbox') {
    const boolVal = value === true;

    return (
      <BasicSelect
        data-testid='condition-value'
        value={boolVal ? 'true' : 'false'}
        onChange={e => onChange(e.target.value === 'true')}
      >
        <option value='true'>checked</option>
        <option value='false'>unchecked</option>
      </BasicSelect>
    );
  }

  if (
    (question.type === 'radio' || question.type === 'multi-select') &&
    question.choiceOptions &&
    question.choiceOptions.length > 0
  ) {
    const current = typeof value === 'string' ? value : '';

    return (
      <BasicSelect
        data-testid='condition-value'
        value={current}
        onChange={e => onChange(e.target.value)}
      >
        {question.choiceOptions.map(opt => (
          <option key={opt} value={opt}>
            {opt}
          </option>
        ))}
      </BasicSelect>
    );
  }

  if (question.type === 'number') {
    return (
      <InputWrapper>
        <InputStyled
          data-testid='condition-value'
          type='number'
          value={typeof value === 'number' ? value : ''}
          onChange={e =>
            onChange(e.target.value === '' ? '' : Number(e.target.value))
          }
        />
      </InputWrapper>
    );
  }

  if (question.type === 'date') {
    return (
      <InputWrapper>
        <InputStyled
          data-testid='condition-value'
          type='date'
          value={typeof value === 'string' ? value : ''}
          onChange={e => onChange(e.target.value)}
        />
      </InputWrapper>
    );
  }

  return (
    <InputWrapper>
      <InputStyled
        data-testid='condition-value'
        value={
          typeof value === 'string' || typeof value === 'number' ? value : ''
        }
        onChange={e => onChange(e.target.value)}
      />
    </InputWrapper>
  );
}

function defaultValueFor(question: FormQuestionRef): JSONValue {
  if (question.type === 'checkbox') return true;

  if (question.type === 'number') return 0;

  if (question.choiceOptions && question.choiceOptions.length > 0) {
    return question.choiceOptions[0];
  }

  return '';
}

/** Tolerates a raw JSON string (property unresolvable → no json tag). */
function parseConditionValue(raw: JSONValue | undefined): JSONValue {
  if (raw === undefined || raw === null) return '';

  if (typeof raw === 'string') {
    try {
      return JSON.parse(raw) as JSONValue;
    } catch {
      return raw;
    }
  }

  return raw;
}

const AndLabel = styled.p`
  margin: 0.15rem 0;
  font-size: 0.8rem;
  color: ${p => p.theme.colors.textLight};
`;

const AddButton = styled(Button)`
  align-self: flex-start;
  box-shadow: none;
  border: 1px dashed ${p => p.theme.colors.bg2};
  background: none;
`;
