import { Resource } from '@tomic/react';
import { useEffect, useState, type JSX } from 'react';
import Field from '@components/forms/Field';
import { BasicSelect } from '@components/forms/BasicSelect';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { useDebounce } from '@helpers/useDebounce';
import { useFieldOptions, type FieldOptionsBag } from './useFieldOptions';
import { FieldPair } from './FieldPair';

interface OptionsProps {
  field: Resource;
}

/** Answers are `1..scale`; the bounds mirror `likert_scale` in
 * `server/src/forms.rs` (which falls back to 5 for anything outside them). */
const LIKERT_SCALES = [3, 4, 5, 6, 7, 9, 10, 11];
const RATING_MAXIMA = [3, 4, 5, 6, 7, 8, 9, 10];

export function LikertOptions({ field }: OptionsProps): JSX.Element {
  const [options, setOptions] = useFieldOptions(field);

  return (
    <>
      <Field label='Scale'>
        <BasicSelect
          value={String((options.scale as number | undefined) ?? 5)}
          onChange={e =>
            setOptions({ ...options, scale: Number(e.target.value) })
          }
        >
          {LIKERT_SCALES.map(scale => (
            <option key={scale} value={scale}>
              {scale} points
            </option>
          ))}
        </BasicSelect>
      </Field>
      <FieldPair>
        <LabelInput
          label='Low end label'
          optionKey='minLabel'
          options={options}
          setOptions={setOptions}
          resetKey={field.subject}
        />
        <LabelInput
          label='High end label'
          optionKey='maxLabel'
          options={options}
          setOptions={setOptions}
          resetKey={field.subject}
        />
      </FieldPair>
    </>
  );
}

export function RatingOptions({ field }: OptionsProps): JSX.Element {
  const [options, setOptions] = useFieldOptions(field);

  return (
    <FieldPair>
      <Field label='Steps'>
        <BasicSelect
          value={String((options.max as number | undefined) ?? 5)}
          onChange={e =>
            setOptions({ ...options, max: Number(e.target.value) })
          }
        >
          {RATING_MAXIMA.map(max => (
            <option key={max} value={max}>
              {max}
            </option>
          ))}
        </BasicSelect>
      </Field>
      <Field label='Icon'>
        <BasicSelect
          value={(options.icon as string | undefined) ?? 'star'}
          onChange={e => setOptions({ ...options, icon: e.target.value })}
        >
          <option value='star'>★ Star</option>
          <option value='heart'>♥ Heart</option>
        </BasicSelect>
      </Field>
    </FieldPair>
  );
}

interface LabelInputProps {
  label: string;
  optionKey: 'minLabel' | 'maxLabel';
  options: FieldOptionsBag;
  setOptions: (next: FieldOptionsBag) => void;
  resetKey: string;
}

/** Debounced like the other free-text option editors — see StringListEditor. */
function LabelInput({
  label,
  optionKey,
  options,
  setOptions,
  resetKey,
}: LabelInputProps): JSX.Element {
  const stored = (options[optionKey] as string | undefined) ?? '';
  const [draft, setDraft] = useState(stored);
  const debounced = useDebounce(draft, 150);

  useEffect(() => {
    setDraft(stored);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resetKey]);

  useEffect(() => {
    if (debounced !== stored) {
      setOptions({ ...options, [optionKey]: debounced });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debounced]);

  return (
    <Field label={label}>
      <InputWrapper>
        <InputStyled value={draft} onChange={e => setDraft(e.target.value)} />
      </InputWrapper>
    </Field>
  );
}
