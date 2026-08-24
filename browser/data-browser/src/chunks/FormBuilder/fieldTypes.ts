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
  FaEarthEurope,
  FaPhone,
  FaLink,
  FaMoneyBill,
  FaSquareCaretDown,
  FaRectangleList,
  FaSliders,
  FaStar,
  FaImages,
  FaBorderAll,
  FaTableList,
  FaLocationDot,
} from 'react-icons/fa6';

/** Input question types: the must-have set (Phase 2) plus the extended set
 * (Phase 6, `planning/form-field-types.md`). Keep in lockstep with
 * `FieldType` in `@tomic/form-renderer` and the `coerce_value` arms in
 * `server/src/forms.rs`. */
export type FormFieldType =
  | 'short-text'
  | 'long-text'
  | 'email'
  | 'number'
  | 'date'
  | 'datetime'
  | 'checkbox'
  | 'radio'
  | 'multi-select'
  | 'phone'
  | 'country'
  | 'url'
  | 'currency'
  | 'dropdown'
  | 'dropdown-multi'
  | 'likert'
  | 'rating'
  | 'picture-choice'
  | 'choice-matrix'
  | 'table-input'
  | 'address';

/** Non-input layout blocks that live in the same `form-fields` array. */
export type FormLayoutType = 'heading' | 'paragraph';

export type AddableFieldType = FormFieldType | FormLayoutType;

/** Add-menu grouping: related question types sit together, separated by a
 * divider. Also the single source of order for [FORM_FIELD_TYPES]. */
export const FIELD_TYPE_GROUPS: FormFieldType[][] = [
  ['short-text', 'long-text', 'email', 'phone', 'url'],
  ['number', 'currency', 'rating', 'likert'],
  [
    'checkbox',
    'radio',
    'dropdown',
    'multi-select',
    'dropdown-multi',
    'picture-choice',
  ],
  ['date', 'datetime'],
  ['choice-matrix', 'table-input', 'address', 'country'],
];

export const FORM_FIELD_TYPES: FormFieldType[] = FIELD_TYPE_GROUPS.flat();

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
  phone: Datatype.STRING,
  country: Datatype.STRING,
  url: Datatype.STRING,
  currency: Datatype.FLOAT,
  dropdown: Datatype.STRING,
  'dropdown-multi': Datatype.JSON,
  likert: Datatype.INTEGER,
  rating: Datatype.INTEGER,
  'picture-choice': Datatype.STRING,
  'choice-matrix': Datatype.JSON,
  'table-input': Datatype.JSON,
  address: Datatype.JSON,
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
  phone: { placeholder: '' },
  country: { placeholder: '' },
  url: { placeholder: 'https://' },
  currency: { currency: 'EUR', placeholder: '' },
  dropdown: { options: ['Option 1', 'Option 2'] },
  'dropdown-multi': { options: ['Option 1', 'Option 2'] },
  likert: {
    scale: 5,
    minLabel: 'Strongly disagree',
    maxLabel: 'Strongly agree',
  },
  rating: { max: 5, icon: 'star' },
  'picture-choice': {
    options: ['Option 1', 'Option 2'],
    optionImages: ['', ''],
  },
  'choice-matrix': {
    rows: ['Statement 1', 'Statement 2'],
    columns: ['Disagree', 'Neutral', 'Agree'],
  },
  'table-input': {
    columns: [
      { label: 'Column 1', type: 'text' },
      { label: 'Column 2', type: 'text' },
    ],
  },
  address: {},
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
  phone: { label: 'Phone number', icon: FaPhone },
  country: { label: 'Country', icon: FaEarthEurope },
  url: { label: 'URL', icon: FaLink },
  currency: { label: 'Currency', icon: FaMoneyBill },
  dropdown: { label: 'Dropdown', icon: FaSquareCaretDown },
  'dropdown-multi': { label: 'Dropdown multi-select', icon: FaRectangleList },
  likert: { label: 'Likert scale', icon: FaSliders },
  rating: { label: 'Rating', icon: FaStar },
  'picture-choice': { label: 'Picture choice', icon: FaImages },
  'choice-matrix': { label: 'Choice matrix', icon: FaBorderAll },
  'table-input': { label: 'Table', icon: FaTableList },
  address: { label: 'Address', icon: FaLocationDot },
  heading: { label: 'Heading', icon: FaHeading },
  paragraph: { label: 'Paragraph', icon: FaParagraph },
};
