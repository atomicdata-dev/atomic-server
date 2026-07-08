import { Datatype, type JSONValue } from '@tomic/react';
import { IconType } from 'react-icons';
import {
  FaFont,
  FaAlignLeft,
  FaEnvelope,
  FaHashtag,
  FaCalendar,
  FaCalendarDays,
  FaRegSquareCheck,
  FaCircleDot,
  FaListCheck,
  FaHeading,
  FaParagraph,
} from 'react-icons/fa6';

/** The must-have set of input question types (Phase 2). */
export type FormFieldType =
  | 'short-text'
  | 'long-text'
  | 'email'
  | 'number'
  | 'date'
  | 'datetime'
  | 'checkbox'
  | 'radio'
  | 'multi-select';

/** Non-input layout blocks that live in the same `form-fields` array. */
export type FormLayoutType = 'heading' | 'paragraph';

export type AddableFieldType = FormFieldType | FormLayoutType;

export const FORM_FIELD_TYPES: FormFieldType[] = [
  'short-text',
  'long-text',
  'email',
  'number',
  'date',
  'datetime',
  'checkbox',
  'radio',
  'multi-select',
];

export const FORM_LAYOUT_TYPES: FormLayoutType[] = ['heading', 'paragraph'];

export function isLayoutType(type: AddableFieldType): type is FormLayoutType {
  return type === 'heading' || type === 'paragraph';
}

/** Maps a question type to the `Datatype` of the Property generated for it. */
export const FIELD_TYPE_TO_DATATYPE: Record<FormFieldType, Datatype> = {
  'short-text': Datatype.STRING,
  'long-text': Datatype.STRING,
  email: Datatype.STRING,
  number: Datatype.FLOAT,
  date: Datatype.DATE,
  datetime: Datatype.TIMESTAMP,
  checkbox: Datatype.BOOLEAN,
  radio: Datatype.STRING,
  'multi-select': Datatype.JSON,
};

/** The `form-field-options` JSON a freshly created field of this type starts with. */
export const FIELD_TYPE_DEFAULT_OPTIONS: Record<FormFieldType, JSONValue> = {
  'short-text': { placeholder: '' },
  'long-text': { placeholder: '' },
  email: { placeholder: '' },
  number: { placeholder: '' },
  date: {},
  datetime: {},
  checkbox: { defaultValue: false },
  radio: { options: ['Option 1', 'Option 2'] },
  'multi-select': { options: ['Option 1', 'Option 2'] },
};

interface FieldTypeMeta {
  label: string;
  icon: IconType;
}

export const FIELD_TYPE_META: Record<AddableFieldType, FieldTypeMeta> = {
  'short-text': { label: 'Short text', icon: FaFont },
  'long-text': { label: 'Long text', icon: FaAlignLeft },
  email: { label: 'Email', icon: FaEnvelope },
  number: { label: 'Number', icon: FaHashtag },
  date: { label: 'Date', icon: FaCalendar },
  datetime: { label: 'Date & time', icon: FaCalendarDays },
  checkbox: { label: 'Checkbox', icon: FaRegSquareCheck },
  radio: { label: 'Radio group', icon: FaCircleDot },
  'multi-select': { label: 'Multi-select', icon: FaListCheck },
  heading: { label: 'Heading', icon: FaHeading },
  paragraph: { label: 'Paragraph', icon: FaParagraph },
};
