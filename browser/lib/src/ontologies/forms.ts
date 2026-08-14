/* -----------------------------------
 * Hand-written to mirror the output of @tomic/cli, generated from lib/defaults/forms.json.
 * For more info on how to use ontologies: https://github.com/atomicdata-dev/atomic-server/blob/develop/browser/cli/readme.md
 * -------------------------------- */

import type { OntologyBaseObject, BaseProps, JSONValue } from '../index.js';

export const forms = {
  classes: {
    form: 'https://atomicdata.dev/classes/Form',
    formPage: 'https://atomicdata.dev/classes/FormPage',
    formField: 'https://atomicdata.dev/classes/FormField',
    formHeading: 'https://atomicdata.dev/classes/FormHeading',
    formParagraph: 'https://atomicdata.dev/classes/FormParagraph',
    formInviteCode: 'https://atomicdata.dev/classes/FormInviteCode',
    formCondition: 'https://atomicdata.dev/classes/FormCondition',
  },
  properties: {
    formDataClass: 'https://atomicdata.dev/properties/form-data-class',
    formTargetTable: 'https://atomicdata.dev/properties/form-target-table',
    formPages: 'https://atomicdata.dev/properties/form-pages',
    formPublishedAt: 'https://atomicdata.dev/properties/form-published-at',
    formSettings: 'https://atomicdata.dev/properties/form-settings',
    formPublishId: 'https://atomicdata.dev/properties/form-publish-id',
    formFields: 'https://atomicdata.dev/properties/form-fields',
    coverImage: 'https://atomicdata.dev/properties/cover-image',
    imagePosition: 'https://atomicdata.dev/properties/image-position',
    formMapsTo: 'https://atomicdata.dev/properties/form-maps-to',
    required: 'https://atomicdata.dev/properties/required',
    formFieldType: 'https://atomicdata.dev/properties/form-field-type',
    formFieldOptions: 'https://atomicdata.dev/properties/form-field-options',
    formStyling: 'https://atomicdata.dev/properties/form-styling',
    formSubmissionSummary:
      'https://atomicdata.dev/properties/form-submission-summary',
    formAccess: 'https://atomicdata.dev/properties/form-access',
    formCode: 'https://atomicdata.dev/properties/form-code',
    usedAt: 'https://atomicdata.dev/properties/used-at',
    formConditions: 'https://atomicdata.dev/properties/form-conditions',
    formConditionField: 'https://atomicdata.dev/properties/form-condition-field',
    formConditionOperator:
      'https://atomicdata.dev/properties/form-condition-operator',
    formConditionValue: 'https://atomicdata.dev/properties/form-condition-value',
  },
  __classDefs: {
    ['https://atomicdata.dev/classes/Form']: [
      'https://atomicdata.dev/properties/name',
      'https://atomicdata.dev/properties/form-data-class',
      'https://atomicdata.dev/properties/form-target-table',
      'https://atomicdata.dev/properties/form-pages',
      'https://atomicdata.dev/properties/form-published-at',
      'https://atomicdata.dev/properties/form-settings',
      'https://atomicdata.dev/properties/form-publish-id',
      'https://atomicdata.dev/properties/form-styling',
      'https://atomicdata.dev/properties/form-access',
      'https://atomicdata.dev/properties/cover-image',
      'https://atomicdata.dev/properties/image-position',
    ],
    ['https://atomicdata.dev/classes/FormPage']: [
      'https://atomicdata.dev/properties/form-fields',
      'https://atomicdata.dev/properties/name',
      'https://atomicdata.dev/properties/cover-image',
      'https://atomicdata.dev/properties/image-position',
      'https://atomicdata.dev/properties/form-conditions',
    ],
    ['https://atomicdata.dev/classes/FormField']: [
      'https://atomicdata.dev/properties/name',
      'https://atomicdata.dev/properties/form-maps-to',
      'https://atomicdata.dev/properties/form-field-type',
      'https://atomicdata.dev/properties/description',
      'https://atomicdata.dev/properties/required',
      'https://atomicdata.dev/properties/form-field-options',
      'https://atomicdata.dev/properties/form-conditions',
    ],
    ['https://atomicdata.dev/classes/FormHeading']: [
      'https://atomicdata.dev/properties/name',
      'https://atomicdata.dev/properties/form-conditions',
    ],
    ['https://atomicdata.dev/classes/FormParagraph']: [
      'https://atomicdata.dev/properties/description',
      'https://atomicdata.dev/properties/form-conditions',
    ],
    ['https://atomicdata.dev/classes/FormInviteCode']: [
      'https://atomicdata.dev/properties/form-code',
      'https://atomicdata.dev/properties/used-at',
    ],
    ['https://atomicdata.dev/classes/FormCondition']: [
      'https://atomicdata.dev/properties/form-condition-field',
      'https://atomicdata.dev/properties/form-condition-operator',
      'https://atomicdata.dev/properties/form-condition-value',
    ],
  },
} as const satisfies OntologyBaseObject;

// eslint-disable-next-line @typescript-eslint/no-namespace
export namespace Forms {
  export type Form = typeof forms.classes.form;
  export type FormPage = typeof forms.classes.formPage;
  export type FormField = typeof forms.classes.formField;
  export type FormHeading = typeof forms.classes.formHeading;
  export type FormParagraph = typeof forms.classes.formParagraph;
  export type FormInviteCode = typeof forms.classes.formInviteCode;
  export type FormCondition = typeof forms.classes.formCondition;
}

declare module '../index.js' {
  interface Classes {
    [forms.classes.form]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/name'
        | typeof forms.properties.formDataClass
        | typeof forms.properties.formTargetTable
        | typeof forms.properties.formPages;
      recommends:
        | typeof forms.properties.formPublishedAt
        | typeof forms.properties.formSettings
        | typeof forms.properties.formPublishId
        | typeof forms.properties.formStyling
        | typeof forms.properties.formAccess
        | typeof forms.properties.coverImage
        | typeof forms.properties.imagePosition;
    };
    [forms.classes.formPage]: {
      requires: BaseProps | typeof forms.properties.formFields;
      recommends:
        | 'https://atomicdata.dev/properties/name'
        | typeof forms.properties.coverImage
        | typeof forms.properties.imagePosition
        | typeof forms.properties.formConditions;
    };
    [forms.classes.formField]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/name'
        | typeof forms.properties.formMapsTo
        | typeof forms.properties.formFieldType;
      recommends:
        | 'https://atomicdata.dev/properties/description'
        | typeof forms.properties.required
        | typeof forms.properties.formFieldOptions
        | typeof forms.properties.formConditions;
    };
    [forms.classes.formHeading]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/name';
      recommends: typeof forms.properties.formConditions;
    };
    [forms.classes.formParagraph]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/description';
      recommends: typeof forms.properties.formConditions;
    };
    [forms.classes.formInviteCode]: {
      requires: BaseProps | typeof forms.properties.formCode;
      recommends: typeof forms.properties.usedAt;
    };
    [forms.classes.formCondition]: {
      requires:
        | BaseProps
        | typeof forms.properties.formConditionField
        | typeof forms.properties.formConditionOperator;
      recommends: typeof forms.properties.formConditionValue;
    };
  }

  interface PropTypeMapping {
    [forms.properties.formDataClass]: string;
    [forms.properties.formTargetTable]: string;
    [forms.properties.formPages]: string[];
    [forms.properties.formPublishedAt]: number;
    [forms.properties.formSettings]: JSONValue;
    [forms.properties.formPublishId]: string;
    [forms.properties.formFields]: string[];
    [forms.properties.coverImage]: string;
    [forms.properties.imagePosition]: string;
    [forms.properties.formMapsTo]: string;
    [forms.properties.required]: boolean;
    [forms.properties.formFieldType]: string;
    [forms.properties.formFieldOptions]: JSONValue;
    [forms.properties.formStyling]: JSONValue;
    [forms.properties.formSubmissionSummary]: JSONValue;
    [forms.properties.formAccess]: string;
    [forms.properties.formCode]: string;
    [forms.properties.usedAt]: number;
    [forms.properties.formConditions]: string[];
    [forms.properties.formConditionField]: string;
    [forms.properties.formConditionOperator]: string;
    [forms.properties.formConditionValue]: JSONValue;
  }

  interface PropSubjectToNameMapping {
    [forms.properties.formDataClass]: 'formDataClass';
    [forms.properties.formTargetTable]: 'formTargetTable';
    [forms.properties.formPages]: 'formPages';
    [forms.properties.formPublishedAt]: 'formPublishedAt';
    [forms.properties.formSettings]: 'formSettings';
    [forms.properties.formPublishId]: 'formPublishId';
    [forms.properties.formFields]: 'formFields';
    [forms.properties.coverImage]: 'coverImage';
    [forms.properties.imagePosition]: 'imagePosition';
    [forms.properties.formMapsTo]: 'formMapsTo';
    [forms.properties.required]: 'required';
    [forms.properties.formFieldType]: 'formFieldType';
    [forms.properties.formFieldOptions]: 'formFieldOptions';
    [forms.properties.formStyling]: 'formStyling';
    [forms.properties.formSubmissionSummary]: 'formSubmissionSummary';
    [forms.properties.formAccess]: 'formAccess';
    [forms.properties.formCode]: 'formCode';
    [forms.properties.usedAt]: 'usedAt';
    [forms.properties.formConditions]: 'formConditions';
    [forms.properties.formConditionField]: 'formConditionField';
    [forms.properties.formConditionOperator]: 'formConditionOperator';
    [forms.properties.formConditionValue]: 'formConditionValue';
  }
}
