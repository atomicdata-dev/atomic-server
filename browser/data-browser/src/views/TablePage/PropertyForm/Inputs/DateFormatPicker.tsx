import { urls } from '@tomic/react';
import React from 'react';
import { styled } from 'styled-components';
import { RadioInput } from '../../../../components/forms/RadioInput';
import { formatDate } from '../../../../helpers/dates/formatDate';

const {
  instances: { dateFormats },
} = urls;

interface DateFormatPickerProps {
  value?: string;
  onChange: (value: string) => void;
  withTime?: boolean;
}

const EXAMPLE_DATE_OFFSET = 1000 * 60 * 60 * 15;
const EXAMPLE_DATE = new Date(Date.now() - EXAMPLE_DATE_OFFSET);

export function DateFormatPicker({
  value,
  onChange,
  withTime = false,
}: DateFormatPickerProps): JSX.Element {
  return (
    <Wrapper>
      <OptionWrapper>
        <RadioInput
          type='radio'
          name='date-format'
          value={dateFormats.localNumeric}
          checked={value === dateFormats.localNumeric}
          onChange={() => onChange(dateFormats.localNumeric)}
        >
          Numeric
        </RadioInput>
        <FormattedDate>
          {formatDate(dateFormats.localNumeric, EXAMPLE_DATE, withTime)}
        </FormattedDate>
      </OptionWrapper>
      <OptionWrapper>
        <RadioInput
          type='radio'
          name='date-format'
          value={dateFormats.localLong}
          checked={value === dateFormats.localLong}
          onChange={() => onChange(dateFormats.localLong)}
        >
          Long
        </RadioInput>
        <FormattedDate>
          {formatDate(dateFormats.localLong, EXAMPLE_DATE, withTime)}
        </FormattedDate>
      </OptionWrapper>
      <OptionWrapper>
        <RadioInput
          type='radio'
          name='date-format'
          value={dateFormats.localRelative}
          checked={value === dateFormats.localRelative}
          onChange={() => onChange(dateFormats.localRelative)}
        >
          Relative
        </RadioInput>
        <FormattedDate>
          {formatDate(dateFormats.localRelative, EXAMPLE_DATE, withTime)}
        </FormattedDate>
      </OptionWrapper>
    </Wrapper>
  );
}

const Wrapper = styled.div`
  display: flex;
  flex-direction: column;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
`;

const OptionWrapper = styled.div`
  padding: ${p => p.theme.margin}rem;

  &:not(:last-child) {
    border-bottom: 1px solid ${p => p.theme.colors.bg2};
  }
`;

const FormattedDate = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-style: italic;
`;
