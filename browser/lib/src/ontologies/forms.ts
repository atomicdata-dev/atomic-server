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
    ],
    ['https://atomicdata.dev/classes/FormPage']: [
      'https://atomicdata.dev/properties/form-fields',
      'https://atomicdata.dev/properties/name',
      'https://atomicdata.dev/properties/cover-image',
      'https://atomicdata.dev/properties/image-position',
    ],
    ['https://atomicdata.dev/classes/FormField']: [
      'https://atomicdata.dev/properties/name',
      'https://atomicdata.dev/properties/form-maps-to',
      'https://atomicdata.dev/properties/form-field-type',
      'https://atomicdata.dev/properties/description',
      'https://atomicdata.dev/properties/required',
      'https://atomicdata.dev/properties/form-field-options',
    ],
    ['https://atomicdata.dev/classes/FormHeading']: [
      'https://atomicdata.dev/properties/name',
    ],
    ['https://atomicdata.dev/classes/FormParagraph']: [
      'https://atomicdata.dev/properties/description',
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
        | typeof forms.properties.formPublishId;
    };
    [forms.classes.formPage]: {
      requires: BaseProps | typeof forms.properties.formFields;
      recommends:
        | 'https://atomicdata.dev/properties/name'
        | typeof forms.properties.coverImage
        | typeof forms.properties.imagePosition;
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
        | typeof forms.properties.formFieldOptions;
    };
    [forms.classes.formHeading]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/name';
      recommends: never;
    };
    [forms.classes.formParagraph]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/description';
      recommends: never;
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
  }
}
